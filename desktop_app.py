#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET DESKTOP v6.2
Standalone GUI application — tkinter (stdlib, no extra deps).
Runs the async node in a background thread; UI updates via after().

Launch:
    python desktop_app.py [--port PORT] [--data-dir DIR]
or (after PyInstaller build):
    murnet-desktop.exe / murnet-desktop
"""

import argparse
import asyncio
import queue
import sys
import threading
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

# ---------------------------------------------------------------------------
# tkinter — required; show a friendly error if missing
# ---------------------------------------------------------------------------
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, simpledialog
except ImportError:
    print("ERROR: tkinter is required. On Linux: sudo apt install python3-tk")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
BG          = "#1e1e2e"
BG2         = "#2a2a3e"
BG3         = "#313244"
FG          = "#cdd6f4"
FG_DIM      = "#6c7086"
ACCENT      = "#89b4fa"
ACCENT2     = "#cba6f7"
GREEN       = "#a6e3a1"
RED         = "#f38ba8"
YELLOW      = "#f9e2af"
FONT_MAIN   = ("Consolas", 11)
FONT_TITLE  = ("Consolas", 13, "bold")
FONT_SMALL  = ("Consolas", 9)


# ---------------------------------------------------------------------------
# Event bus between node thread and UI thread
# ---------------------------------------------------------------------------
class EventBus:
    def __init__(self):
        self._q: queue.Queue = queue.Queue()

    def post(self, event_type: str, data=None):
        self._q.put_nowait({"type": event_type, "data": data, "ts": time.time()})

    def drain(self):
        events = []
        while not self._q.empty():
            events.append(self._q.get_nowait())
        return events


# ---------------------------------------------------------------------------
# Node runner (background thread)
# ---------------------------------------------------------------------------
class NodeRunner:
    def __init__(self, data_dir: str, port: int, bus: EventBus):
        self.data_dir = data_dir
        self.port = port
        self.bus = bus
        self.node = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._password: Optional[str] = None   # set by PasswordDialog before start()

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="NodeThread")
        self._thread.start()

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._async_main())
        self._loop.run_forever()

    async def _async_main(self):
        from core.node.async_node import AsyncMurnetNode
        from core.identity.keystore import WrongPasswordError
        try:
            self.node = AsyncMurnetNode(
                data_dir=self.data_dir,
                port=self.port,
                password=self._password,
            )
        except WrongPasswordError as exc:
            self.bus.post("auth_failed", {"reason": str(exc)})
            return
        self.node.on_message_received = self._on_message
        await self.node.start()
        self.bus.post("node_ready", {"address": self.node.address})

    def _on_message(self, from_addr: str, to_addr: str, text: str):
        self.bus.post("message_received", {
            "from": from_addr,
            "to": to_addr,
            "text": text,
            "ts": time.time(),
        })

    def call(self, coro):
        """Run a coroutine in node's loop; returns result (blocks caller)."""
        if not self._loop:
            return None
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=10)
        except Exception as exc:
            return None

    def stop(self):
        if self._loop and self.node:
            asyncio.run_coroutine_threadsafe(self.node.stop(), self._loop)


# ---------------------------------------------------------------------------
# Widgets helpers
# ---------------------------------------------------------------------------
def _style_widget(w, bg=BG2, fg=FG, font=FONT_MAIN):
    try:
        w.configure(bg=bg, fg=fg, font=font,
                    insertbackground=FG, relief=tk.FLAT,
                    highlightthickness=1, highlightbackground=BG3)
    except tk.TclError:
        pass


def _btn(parent, text: str, cmd, width=12, accent=False):
    b = tk.Button(
        parent, text=text, command=cmd,
        bg=ACCENT if accent else BG3,
        fg=BG if accent else FG,
        font=FONT_MAIN, relief=tk.FLAT,
        activebackground=ACCENT2,
        activeforeground=BG,
        cursor="hand2",
        padx=8, pady=4,
        width=width,
    )
    return b


# ---------------------------------------------------------------------------
# Password dialog (shown before node starts)
# ---------------------------------------------------------------------------

class PasswordDialog(tk.Toplevel):
    """
    Модальный диалог пароля.

    Режимы:
    - ``mode="create"``  — первый запуск, два поля (пароль + подтверждение)
    - ``mode="unlock"``  — повторный запуск, одно поле
    - ``mode="change"``  — смена пароля (старый + новый + подтверждение)

    После закрытия:
      ``dialog.password``  — введённый пароль или ``None`` если отменено
    """

    _MIN_LEN = 8

    def __init__(self, parent: tk.Tk, mode: str = "unlock", data_dir: str = "."):
        super().__init__(parent)
        self.mode = mode
        self.data_dir = data_dir
        self.password: Optional[str] = None

        self.title("Murnet — Защита узла")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.grab_set()  # modal

        self._build()
        self._center(parent)
        self.wait_window()

    # ------------------------------------------------------------------

    def _center(self, parent: tk.Tk):
        self.update_idletasks()
        px, py = parent.winfo_x(), parent.winfo_y()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        self.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")

    def _build(self):
        # ---- Icon + title -------------------------------------------
        icon_lbl = tk.Label(self, text="🔐", bg=BG, font=("Consolas", 32))
        icon_lbl.pack(pady=(18, 0))

        if self.mode == "create":
            head = "Создайте пароль для узла"
            sub  = "БЕЗ ПАРОЛЯ ДОСТУП К УЗЛУ БУДЕТ НЕВОЗМОЖЕН"
        elif self.mode == "change":
            head = "Смена пароля"
            sub  = "Введите текущий пароль, затем новый"
        else:
            head = "Введите пароль"
            sub  = "Пароль защищает приватный ключ узла"

        tk.Label(self, text=head, bg=BG, fg=ACCENT,
                 font=FONT_TITLE).pack(pady=(4, 0))
        tk.Label(self, text=sub, bg=BG, fg=RED if self.mode == "create" else FG_DIM,
                 font=FONT_SMALL).pack(pady=(2, 10))

        # ---- Fields -------------------------------------------------
        form = tk.Frame(self, bg=BG, padx=30)
        form.pack(fill=tk.X)

        def _field(label: str, show: str = "*") -> tk.Entry:
            tk.Label(form, text=label, bg=BG, fg=FG, font=FONT_MAIN,
                     anchor=tk.W).pack(fill=tk.X, pady=(6, 0))
            e = tk.Entry(form, bg=BG2, fg=FG, font=FONT_MAIN,
                         insertbackground=FG, relief=tk.FLAT,
                         highlightthickness=1, highlightbackground=ACCENT,
                         show=show, width=30)
            e.pack(fill=tk.X, ipady=4, pady=(2, 0))
            return e

        self._e_old = None
        if self.mode == "change":
            self._e_old = _field("Текущий пароль:")

        self._e_pw = _field(
            "Новый пароль (мин. 8 симв.):" if self.mode in ("create", "change")
            else "Пароль:"
        )
        self._e_pw.bind("<Return>", self._focus_next)

        self._e_confirm = None
        if self.mode in ("create", "change"):
            self._e_confirm = _field("Подтвердите пароль:")
            self._e_confirm.bind("<Return>", lambda _: self._on_ok())

        # Show/hide toggle
        self._show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(form, text="Показать пароль", variable=self._show_var,
                       bg=BG, fg=FG_DIM, selectcolor=BG2, font=FONT_SMALL,
                       activebackground=BG, activeforeground=FG,
                       command=self._toggle_show).pack(anchor=tk.W, pady=(6, 0))

        # ---- Error label --------------------------------------------
        self._err_var = tk.StringVar()
        tk.Label(self, textvariable=self._err_var, bg=BG, fg=RED,
                 font=FONT_SMALL, wraplength=320).pack(pady=(4, 0), padx=30)

        # ---- Buttons ------------------------------------------------
        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(pady=(12, 18), padx=30, fill=tk.X)
        _btn(btn_row, "Отмена", self._on_cancel, width=10).pack(side=tk.RIGHT, padx=4)
        _btn(btn_row, "OK", self._on_ok, width=10, accent=True).pack(side=tk.RIGHT)

        self._e_pw.focus_set()

    def _toggle_show(self):
        char = "" if self._show_var.get() else "*"
        self._e_pw.configure(show=char)
        if self._e_confirm:
            self._e_confirm.configure(show=char)
        if self._e_old:
            self._e_old.configure(show=char)

    def _focus_next(self, _event=None):
        if self._e_confirm:
            self._e_confirm.focus_set()
        else:
            self._on_ok()

    def _on_ok(self, _event=None):
        pw = self._e_pw.get()

        if self.mode in ("create", "change") and self._e_confirm:
            confirm = self._e_confirm.get()
            if pw != confirm:
                self._err_var.set("Пароли не совпадают.")
                self._e_confirm.delete(0, tk.END)
                self._e_confirm.focus_set()
                return

        if len(pw) < self._MIN_LEN:
            self._err_var.set(f"Пароль слишком короткий (мин. {self._MIN_LEN} симв.).")
            return

        self.password = pw
        # For "change" also return old password via attribute
        if self._e_old:
            self.old_password = self._e_old.get()
        self.destroy()

    def _on_cancel(self):
        self.password = None
        self.destroy()


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------
class MurnetApp(tk.Tk):

    def __init__(self, runner: NodeRunner):
        super().__init__()
        self.runner = runner
        self.bus = runner.bus
        self._current_chat: Optional[str] = None  # address we're chatting with

        self.title("Murnet v6.2")
        self.geometry("1000x680")
        self.minsize(800, 560)
        self.configure(bg=BG)

        self._build_ui()
        self._poll()  # start event polling

        # Show password dialog immediately on startup, before node starts
        self.after(50, self._request_password)

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # ---- Top bar -----------------------------------------------
        topbar = tk.Frame(self, bg=BG2, height=40)
        topbar.pack(fill=tk.X, side=tk.TOP)
        topbar.pack_propagate(False)

        tk.Label(topbar, text="Murnet", bg=BG2, fg=ACCENT,
                 font=FONT_TITLE).pack(side=tk.LEFT, padx=12)
        self._lbl_addr = tk.Label(topbar, text="initializing…",
                                  bg=BG2, fg=FG_DIM, font=FONT_SMALL)
        self._lbl_addr.pack(side=tk.LEFT, padx=8)

        self._lbl_status = tk.Label(topbar, text="● starting",
                                    bg=BG2, fg=YELLOW, font=FONT_SMALL)
        self._lbl_status.pack(side=tk.RIGHT, padx=12)

        # ---- Main panes ---------------------------------------------
        main = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=BG, sashwidth=4,
                              sashrelief=tk.FLAT)
        main.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Left sidebar
        sidebar = tk.Frame(main, bg=BG2, width=220)
        main.add(sidebar, minsize=180)

        # Right chat area
        right = tk.Frame(main, bg=BG)
        main.add(right, minsize=400)

        self._build_sidebar(sidebar)
        self._build_chat(right)

        # ---- Status bar --------------------------------------------
        statusbar = tk.Frame(self, bg=BG3, height=24)
        statusbar.pack(fill=tk.X, side=tk.BOTTOM)
        statusbar.pack_propagate(False)
        self._lbl_bottom = tk.Label(statusbar, text="Ready",
                                    bg=BG3, fg=FG_DIM, font=FONT_SMALL, anchor=tk.W)
        self._lbl_bottom.pack(side=tk.LEFT, padx=8)

    def _build_sidebar(self, parent):
        # Tabs: Peers / Info
        tabs = ttk.Notebook(parent)
        tabs.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ---- Peers tab ---
        peers_frame = tk.Frame(tabs, bg=BG2)
        tabs.add(peers_frame, text="Peers")

        btn_row = tk.Frame(peers_frame, bg=BG2)
        btn_row.pack(fill=tk.X, padx=4, pady=4)
        _btn(btn_row, "Connect", self._dlg_connect, width=8).pack(side=tk.LEFT, padx=2)
        _btn(btn_row, "Refresh", self._refresh_peers, width=8).pack(side=tk.LEFT, padx=2)

        self._peers_list = tk.Listbox(
            peers_frame, bg=BG3, fg=FG, font=FONT_SMALL,
            selectbackground=ACCENT, selectforeground=BG,
            relief=tk.FLAT, borderwidth=0, activestyle="none",
        )
        self._peers_list.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self._peers_list.bind("<Double-Button-1>", self._on_peer_dclick)

        # ---- Info tab ---
        info_frame = tk.Frame(tabs, bg=BG2)
        tabs.add(info_frame, text="Info")

        self._info_text = scrolledtext.ScrolledText(
            info_frame, bg=BG3, fg=FG, font=FONT_SMALL,
            state=tk.DISABLED, relief=tk.FLAT, borderwidth=0,
        )
        self._info_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Style scrollbar
        self._info_text.vbar.configure(bg=BG3, troughcolor=BG2, width=6)

        _btn(info_frame, "Refresh Info",   self._refresh_info,    width=14).pack(pady=(4, 2))
        _btn(info_frame, "Сменить пароль", self._change_password, width=14).pack(pady=(0, 4))

        # ---- Objects tab (v6.2) ---
        obj_frame = tk.Frame(tabs, bg=BG2)
        tabs.add(obj_frame, text="Objects")

        obj_btn_row = tk.Frame(obj_frame, bg=BG2)
        obj_btn_row.pack(fill=tk.X, padx=4, pady=4)
        _btn(obj_btn_row, "Refresh", self._refresh_objects, width=8).pack(side=tk.LEFT, padx=2)
        _btn(obj_btn_row, "Publish…", self._dlg_publish, width=8).pack(side=tk.LEFT, padx=2)

        self._obj_list = tk.Listbox(
            obj_frame, bg=BG3, fg=FG, font=FONT_SMALL,
            selectbackground=ACCENT, selectforeground=BG,
            relief=tk.FLAT, borderwidth=0, activestyle="none",
        )
        self._obj_list.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

    def _build_chat(self, parent):
        # Chat header
        header = tk.Frame(parent, bg=BG3, height=36)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        self._lbl_chat_peer = tk.Label(header, text="Select a peer to chat",
                                       bg=BG3, fg=ACCENT, font=FONT_MAIN)
        self._lbl_chat_peer.pack(side=tk.LEFT, padx=12, pady=6)

        # Message history
        self._chat_log = scrolledtext.ScrolledText(
            parent, bg=BG, fg=FG, font=FONT_MAIN,
            state=tk.DISABLED, relief=tk.FLAT, wrap=tk.WORD,
        )
        self._chat_log.pack(fill=tk.BOTH, expand=True, padx=0)
        self._chat_log.tag_config("me",     foreground=ACCENT)
        self._chat_log.tag_config("them",   foreground=GREEN)
        self._chat_log.tag_config("system", foreground=FG_DIM)
        self._chat_log.tag_config("time",   foreground=FG_DIM, font=FONT_SMALL)

        # Input row
        input_row = tk.Frame(parent, bg=BG3)
        input_row.pack(fill=tk.X, side=tk.BOTTOM)

        self._entry = tk.Entry(input_row, bg=BG2, fg=FG, font=FONT_MAIN,
                               insertbackground=FG, relief=tk.FLAT,
                               highlightthickness=1, highlightbackground=ACCENT)
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, pady=8, ipady=4)
        self._entry.bind("<Return>", self._on_send)

        _btn(input_row, "Send", self._on_send, width=8, accent=True).pack(
            side=tk.RIGHT, padx=8, pady=8)

        # Extra buttons
        extra = tk.Frame(parent, bg=BG)
        extra.pack(fill=tk.X)
        _btn(extra, "Send to Addr…", self._dlg_send_addr, width=14).pack(side=tk.LEFT, padx=6, pady=4)
        _btn(extra, "Register Name", self._dlg_register, width=14).pack(side=tk.LEFT, padx=2)
        _btn(extra, "Lookup Name",   self._dlg_lookup,   width=14).pack(side=tk.LEFT, padx=2)

    # ------------------------------------------------------------------
    # Event polling
    # ------------------------------------------------------------------

    def _poll(self):
        """Poll the event bus every 200 ms and update UI."""
        for ev in self.bus.drain():
            self._handle_event(ev)
        self.after(200, self._poll)

    # ------------------------------------------------------------------
    # Password / auth
    # ------------------------------------------------------------------

    def _request_password(self):
        """Show password dialog, then start the node."""
        from core.identity.keystore import EncryptedKeystore
        ks = EncryptedKeystore(self.runner.data_dir)
        mode = "unlock" if ks.exists() else "create"

        dlg = PasswordDialog(self, mode=mode, data_dir=self.runner.data_dir)
        if dlg.password is None:
            # User cancelled — close the app
            self.destroy()
            return

        self._lbl_status.configure(text="● unlocking…", fg=YELLOW)
        self.runner._password = dlg.password
        self.runner.start()

    def _change_password(self):
        """Open change-password dialog."""
        from core.identity.keystore import EncryptedKeystore, WrongPasswordError, WeakPasswordError
        ks = EncryptedKeystore(self.runner.data_dir)
        if not ks.exists():
            messagebox.showinfo("Смена пароля", "Узел ещё не защищён паролем.")
            return
        dlg = PasswordDialog(self, mode="change", data_dir=self.runner.data_dir)
        if dlg.password is None:
            return
        try:
            ks.change_password(dlg.old_password, dlg.password)
            messagebox.showinfo("Готово", "Пароль успешно изменён.")
            self._set_bottom("Пароль изменён.")
        except WrongPasswordError:
            messagebox.showerror("Ошибка", "Неверный текущий пароль.")
        except WeakPasswordError as exc:
            messagebox.showerror("Ошибка", str(exc))

    # ------------------------------------------------------------------
    # Event handling
    # ------------------------------------------------------------------

    def _handle_event(self, ev: dict):
        etype = ev["type"]

        if etype == "auth_failed":
            reason = ev["data"].get("reason", "Неверный пароль")
            self._lbl_status.configure(text="● locked", fg=RED)
            # Show dialog again — allow retry
            messagebox.showerror("Доступ закрыт",
                                 f"{reason}\n\nПопробуйте ещё раз.")
            self.after(100, self._request_password)

        elif etype == "node_ready":
            addr = ev["data"]["address"]
            self._lbl_addr.configure(text=addr[:20] + "…")
            self._lbl_status.configure(text="● running", fg=GREEN)
            self._set_bottom(f"Node ready: {addr[:16]}…")
            self._refresh_peers()

        elif etype == "message_received":
            d = ev["data"]
            self._append_chat(
                f"[{_ts(d['ts'])}] ",
                d["from"][:14] + "… : " + d["text"],
                tag_body="them",
            )
            self._set_bottom(f"New message from {d['from'][:12]}…")

    # ------------------------------------------------------------------
    # Sidebar actions
    # ------------------------------------------------------------------

    def _refresh_peers(self):
        node = self.runner.node
        if not node:
            return
        peers = node.get_peers()
        self._peers_list.delete(0, tk.END)
        for p in peers:
            active = "●" if p.get("is_active") else "○"
            self._peers_list.insert(
                tk.END,
                f"{active} {p['address'][:14]}… {p['ip']}:{p['port']}"
            )
        self._peers_list.itemconfig(tk.END)

    def _refresh_info(self):
        node = self.runner.node
        if not node:
            return
        st = node.get_status()
        self._info_text.configure(state=tk.NORMAL)
        self._info_text.delete("1.0", tk.END)
        for k, v in st.items():
            self._info_text.insert(tk.END, f"{k}:\n  {v}\n")
        self._info_text.configure(state=tk.DISABLED)

    def _on_peer_dclick(self, _event):
        idx = self._peers_list.curselection()
        if not idx:
            return
        line = self._peers_list.get(idx[0])
        # Extract address (after ● / ○ and space)
        parts = line.split()
        if len(parts) >= 2:
            self._current_chat = parts[1].rstrip("…")
            self._lbl_chat_peer.configure(
                text=f"Chat with {parts[1]}"
            )

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------

    def _on_send(self, _event=None):
        if not self._current_chat:
            messagebox.showinfo("No peer selected", "Double-click a peer to start chatting.")
            return
        text = self._entry.get().strip()
        if not text:
            return
        self._entry.delete(0, tk.END)

        node = self.runner.node
        if not node:
            return

        msg_id = self.runner.call(node.send_message(self._current_chat, text))
        if msg_id:
            self._append_chat(
                f"[{datetime.now().strftime('%H:%M:%S')}] ",
                f"You: {text}",
                tag_body="me",
            )
        else:
            self._append_chat("", "[Failed to send]", tag_body="system")

    def _append_chat(self, time_str: str, body: str, tag_body: str = "them"):
        self._chat_log.configure(state=tk.NORMAL)
        self._chat_log.insert(tk.END, time_str, "time")
        self._chat_log.insert(tk.END, body + "\n", tag_body)
        self._chat_log.see(tk.END)
        self._chat_log.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Dialogs
    # ------------------------------------------------------------------

    def _dlg_connect(self):
        win = tk.Toplevel(self)
        win.title("Connect to Peer")
        win.configure(bg=BG)
        win.resizable(False, False)

        tk.Label(win, text="IP Address:", bg=BG, fg=FG, font=FONT_MAIN).grid(
            row=0, column=0, padx=12, pady=8, sticky=tk.W)
        ip_var = tk.StringVar()
        tk.Entry(win, textvariable=ip_var, bg=BG2, fg=FG, font=FONT_MAIN,
                 insertbackground=FG, relief=tk.FLAT,
                 highlightthickness=1, highlightbackground=ACCENT).grid(
            row=0, column=1, padx=12, pady=8, ipady=3)

        tk.Label(win, text="Port:", bg=BG, fg=FG, font=FONT_MAIN).grid(
            row=1, column=0, padx=12, pady=4, sticky=tk.W)
        port_var = tk.StringVar(value="8888")
        tk.Entry(win, textvariable=port_var, bg=BG2, fg=FG, font=FONT_MAIN,
                 insertbackground=FG, relief=tk.FLAT, width=8,
                 highlightthickness=1, highlightbackground=ACCENT).grid(
            row=1, column=1, padx=12, pady=4, sticky=tk.W, ipady=3)

        def _do():
            ip = ip_var.get().strip()
            port = int(port_var.get().strip())
            node = self.runner.node
            if node:
                ok = self.runner.call(node.connect_to_peer(ip, port))
                self._set_bottom(f"Connect {'OK' if ok else 'FAILED'} → {ip}:{port}")
                self._refresh_peers()
            win.destroy()

        _btn(win, "Connect", _do, accent=True).grid(
            row=2, column=0, columnspan=2, pady=12)

    def _dlg_send_addr(self):
        addr = simpledialog.askstring("Send Message", "Recipient address:", parent=self)
        if not addr:
            return
        text = simpledialog.askstring("Send Message", "Message:", parent=self)
        if not text:
            return
        node = self.runner.node
        if not node:
            return
        msg_id = self.runner.call(node.send_message(addr.strip(), text))
        self._set_bottom(f"Message {'queued' if msg_id else 'FAILED'}: {addr[:12]}…")

    def _dlg_register(self):
        name = simpledialog.askstring("Register Name", "Your name (e.g. alice):", parent=self)
        if not name:
            return
        node = self.runner.node
        if not node:
            return
        ok = node.register_name(name.strip())
        self._set_bottom(f"Name registration: {'OK' if ok else 'FAILED'}")

    def _dlg_lookup(self):
        name = simpledialog.askstring("Lookup Name", "Name to look up:", parent=self)
        if not name:
            return
        node = self.runner.node
        if not node:
            return
        addr = node.lookup_name(name.strip())
        if addr:
            messagebox.showinfo("Name Lookup", f"{name} → {addr}")
        else:
            messagebox.showinfo("Name Lookup", f"'{name}' not found in DHT.")

    # ------------------------------------------------------------------
    # Objects / Pub-Sub (v6.2)
    # ------------------------------------------------------------------

    def _refresh_objects(self):
        node = self.runner.node
        if not node:
            return
        store = node.object_store
        ids = store.list_ids()
        self._obj_list.delete(0, tk.END)
        for oid in ids:
            obj = store.get(oid)
            if obj:
                self._obj_list.insert(
                    tk.END,
                    f"{obj.type:<10} {obj.id[:14]}… {obj.owner[:10]}…"
                )

    def _dlg_publish(self):
        node = self.runner.node
        if not node:
            messagebox.showwarning("Not ready", "Node is not running yet.")
            return
        topic = simpledialog.askstring("Publish Object", "Topic name:", parent=self)
        if not topic:
            return
        text = simpledialog.askstring("Publish Object", "Text payload:", parent=self)
        if text is None:
            return

        from core.data.objects import MurObject
        from core.identity.identity import NodeIdentity
        identity = NodeIdentity(private_key_bytes=node.identity.to_bytes())
        obj = MurObject.create(
            obj_type="text",
            owner=node.address,
            data={"text": text, "topic": topic},
            identity=identity,
        )

        async def _pub():
            await node.pubsub.async_publish(topic, obj)

        self.runner.call(_pub())
        self._set_bottom(f"Published {obj.id[:12]}… to '{topic}'")
        self._refresh_objects()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_bottom(self, text: str):
        self._lbl_bottom.configure(text=text)


def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="murnet-desktop",
        description="Murnet v6.2 Desktop Application",
    )
    p.add_argument("--port",     type=int, default=8888,    help="P2P UDP port")
    p.add_argument("--data-dir", type=str, default="./data", help="Data directory")
    p.add_argument("--log-level",type=str, default="WARNING",
                   choices=["DEBUG","INFO","WARNING","ERROR"])
    return p


def main():
    import logging
    args = build_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    os.makedirs(args.data_dir, exist_ok=True)
    bus    = EventBus()
    # runner.start() is called by MurnetApp._request_password()
    # after the password dialog is confirmed
    runner = NodeRunner(data_dir=args.data_dir, port=args.port, bus=bus)

    app = MurnetApp(runner)
    app.mainloop()

    runner.stop()


if __name__ == "__main__":
    main()
