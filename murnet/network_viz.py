#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET NETWORK VISUALIZER v6.2
Интерактивная визуализация топологии сети.

Запуск:
    python network_viz.py                          # подключиться к localhost:8080
    python network_viz.py --api http://HOST:8080   # к удалённому API
    python network_viz.py --demo                   # демо-режим (без живого узла)

Управление:
    Мышь:        перетащить узел — изменить позицию
    Колесо мыши: масштабирование
    Пробел:      сбросить вид
    R:           перечитать топологию прямо сейчас
    Q / Esc:     выход
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent))

try:
    import tkinter as tk
    from tkinter import ttk, font as tkfont
except ImportError:
    print("ERROR: tkinter required.  Linux: sudo apt install python3-tk")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Palette (matches desktop_app.py)
# ---------------------------------------------------------------------------
BG       = "#1e1e2e"
BG2      = "#2a2a3e"
BG3      = "#313244"
FG       = "#cdd6f4"
FG_DIM   = "#6c7086"
ACCENT   = "#89b4fa"
ACCENT2  = "#cba6f7"
GREEN    = "#a6e3a1"
RED      = "#f38ba8"
YELLOW   = "#f9e2af"
ORANGE   = "#fab387"
TEAL     = "#94e2d5"

FONT_MAIN  = ("Consolas", 10)
FONT_SMALL = ("Consolas", 8)
FONT_TITLE = ("Consolas", 12, "bold")
FONT_LABEL = ("Consolas", 9)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class VizNode:
    node_id: str          # short address
    address: str          # full base58 address
    ip: str   = "?"
    port: int = 0
    rtt: float = 0.0
    is_local: bool = False   # это наш собственный узел

    # Layout
    x: float = 0.0
    y: float = 0.0
    vx: float = 0.0   # velocity (physics sim)
    vy: float = 0.0
    pinned: bool = False

    # Visual state
    color: str = ACCENT
    radius: int = 22
    pulse: float = 0.0    # animation phase (0..1)


@dataclass
class VizEdge:
    src: str    # address
    dst: str    # address
    rtt: float = 0.0
    active: bool = True


@dataclass
class NetworkSnapshot:
    local_address: str = ""
    local_port: int    = 0
    peers: List[dict]  = field(default_factory=list)
    uptime: float      = 0.0
    messages_sent: int = 0
    messages_received: int = 0
    ts: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------

class APIClient:
    def __init__(self, base_url: str, token: str = ""):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = 4

    def _get(self, path: str) -> Optional[dict]:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url)
        if self._token:
            req.add_header("Authorization", f"Bearer {self._token}")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def health(self) -> bool:
        return self._get("/health") is not None

    def get_snapshot(self) -> Optional[NetworkSnapshot]:
        status = self._get("/network/status")
        peers  = self._get("/network/peers")
        if status is None:
            return None
        node_info = status.get("node", {})
        net_info  = status.get("network", {})
        stats     = status.get("stats", {})
        snap = NetworkSnapshot(
            local_address    = node_info.get("address", "unknown"),
            local_port       = node_info.get("port", 0),
            uptime           = stats.get("uptime", 0),
            messages_sent    = stats.get("messages_sent", 0),
            messages_received= stats.get("messages_received", 0),
        )
        if peers:
            snap.peers = peers
        return snap


# ---------------------------------------------------------------------------
# Demo generator
# ---------------------------------------------------------------------------

def _demo_snapshot(tick: int) -> NetworkSnapshot:
    """Generate a synthetic multi-node snapshot for demo / offline mode."""
    addrs = [
        "1AliceNode1xyz", "1BobNode2abc", "1CharlieNode3",
        "1DaveNode4def", "1EveNode5ghi", "1FrankNode6",
    ]
    snap = NetworkSnapshot(
        local_address = addrs[0],
        local_port    = 8888,
        uptime        = tick * 2.0,
        messages_sent     = tick * 3,
        messages_received = tick * 7,
    )
    # Ring + random extra edges
    random.seed(tick // 10)
    edges = [(addrs[i], addrs[(i+1) % len(addrs)]) for i in range(len(addrs))]
    if tick % 15 < 10:
        edges.append((addrs[0], addrs[3]))
    snap.peers = [
        {
            "address": dst,
            "ip": f"10.0.0.{i+2}",
            "port": 8888 + i,
            "rtt": round(random.uniform(1, 80), 1),
            "is_active": True,
        }
        for i, (_, dst) in enumerate(edges)
        if dst != snap.local_address
    ]
    return snap


# ---------------------------------------------------------------------------
# Physics layout (force-directed)
# ---------------------------------------------------------------------------

class ForceLayout:
    """Simple Fruchterman–Reingold force-directed layout."""

    REPEL  = 8000.0
    SPRING = 0.04
    DAMP   = 0.85
    IDEAL  = 160.0    # ideal edge length (px)
    MAX_V  = 18.0

    def tick(self, nodes: Dict[str, VizNode], edges: List[VizEdge], dt: float = 0.1):
        addrs = list(nodes.keys())

        # Repulsion between all node pairs
        for i, a in enumerate(addrs):
            na = nodes[a]
            for b in addrs[i+1:]:
                nb = nodes[b]
                dx = na.x - nb.x
                dy = na.y - nb.y
                d2 = max(dx*dx + dy*dy, 1.0)
                d  = math.sqrt(d2)
                f  = self.REPEL / d2
                fx, fy = (dx/d)*f, (dy/d)*f
                if not na.pinned:
                    na.vx += fx * dt
                    na.vy += fy * dt
                if not nb.pinned:
                    nb.vx -= fx * dt
                    nb.vy -= fy * dt

        # Spring attraction along edges
        for e in edges:
            na = nodes.get(e.src)
            nb = nodes.get(e.dst)
            if na is None or nb is None:
                continue
            dx = nb.x - na.x
            dy = nb.y - na.y
            d  = max(math.sqrt(dx*dx + dy*dy), 1.0)
            stretch = d - self.IDEAL
            fx = (dx/d) * stretch * self.SPRING
            fy = (dy/d) * stretch * self.SPRING
            if not na.pinned:
                na.vx += fx * dt
                na.vy += fy * dt
            if not nb.pinned:
                nb.vx -= fx * dt
                nb.vy -= fy * dt

        # Integrate velocity
        for n in nodes.values():
            if n.pinned:
                n.vx = n.vy = 0.0
                continue
            n.vx *= self.DAMP
            n.vy *= self.DAMP
            spd = math.sqrt(n.vx**2 + n.vy**2)
            if spd > self.MAX_V:
                n.vx = n.vx / spd * self.MAX_V
                n.vy = n.vy / spd * self.MAX_V
            n.x += n.vx
            n.y += n.vy


# ---------------------------------------------------------------------------
# Main visualizer window
# ---------------------------------------------------------------------------

class NetworkVisualizer(tk.Tk):

    POLL_INTERVAL  = 3000   # ms between API polls
    FRAME_INTERVAL = 40     # ms between canvas redraws (~25 fps)

    def __init__(self, api_client: Optional[APIClient], demo: bool = False):
        super().__init__()
        self._api   = api_client
        self._demo  = demo
        self._tick  = 0

        # Graph state
        self._nodes: Dict[str, VizNode] = {}
        self._edges: List[VizEdge] = []
        self._lock  = threading.Lock()
        self._snap: Optional[NetworkSnapshot] = None
        self._connected = False
        self._last_update = 0.0

        # Viewport
        self._offset_x = 0.0
        self._offset_y = 0.0
        self._scale    = 1.0

        # Drag state
        self._drag_node: Optional[str] = None
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._pan_start_x  = 0
        self._pan_start_y  = 0
        self._panning      = False

        # Hover
        self._hovered: Optional[str] = None

        # Physics
        self._layout = ForceLayout()
        self._physics_on = True

        self._build_window()
        self._build_canvas()
        self._build_sidebar()
        self._build_statusbar()
        self._bind_keys()

        # Start loops
        self.after(100, self._poll_loop)
        self.after(self.FRAME_INTERVAL, self._draw_loop)

    # ------------------------------------------------------------------
    # Window / UI construction
    # ------------------------------------------------------------------

    def _build_window(self):
        self.title("Murnet — Network Visualizer v6.2")
        self.geometry("1100x700")
        self.minsize(800, 500)
        self.configure(bg=BG)

    def _build_canvas(self):
        self._canvas = tk.Canvas(
            self, bg=BG, highlightthickness=0,
            cursor="fleur",
        )
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Mouse bindings on canvas
        self._canvas.bind("<ButtonPress-1>",   self._on_mouse_down)
        self._canvas.bind("<B1-Motion>",        self._on_mouse_drag)
        self._canvas.bind("<ButtonRelease-1>",  self._on_mouse_up)
        self._canvas.bind("<ButtonPress-3>",    self._on_right_click)
        self._canvas.bind("<MouseWheel>",       self._on_scroll)
        self._canvas.bind("<Button-4>",         lambda e: self._zoom(1.1))
        self._canvas.bind("<Button-5>",         lambda e: self._zoom(0.9))
        self._canvas.bind("<Motion>",           self._on_hover)

    def _build_sidebar(self):
        side = tk.Frame(self, bg=BG2, width=240)
        side.pack(side=tk.RIGHT, fill=tk.Y)
        side.pack_propagate(False)

        # ---- Title ---
        tk.Label(side, text="Murnet Network", bg=BG2, fg=ACCENT,
                 font=FONT_TITLE).pack(padx=12, pady=(14, 2), anchor=tk.W)
        tk.Label(side, text="Topology Visualizer", bg=BG2, fg=FG_DIM,
                 font=FONT_SMALL).pack(padx=12, anchor=tk.W)

        ttk.Separator(side, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=10)

        # ---- Network stats ---
        self._stats_frame = tk.Frame(side, bg=BG2)
        self._stats_frame.pack(fill=tk.X, padx=12)
        self._stat_labels: Dict[str, tk.Label] = {}
        for key in ("Узлов", "Соединений", "Аптайм", "Отправлено", "Получено"):
            row = tk.Frame(self._stats_frame, bg=BG2)
            row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=key + ":", bg=BG2, fg=FG_DIM,
                     font=FONT_LABEL, width=12, anchor=tk.W).pack(side=tk.LEFT)
            lbl = tk.Label(row, text="—", bg=BG2, fg=FG,
                           font=FONT_LABEL, anchor=tk.W)
            lbl.pack(side=tk.LEFT)
            self._stat_labels[key] = lbl

        ttk.Separator(side, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=10)

        # ---- Node info panel ---
        tk.Label(side, text="Выбранный узел", bg=BG2, fg=ACCENT2,
                 font=FONT_LABEL).pack(padx=12, anchor=tk.W)
        self._node_info = tk.Text(
            side, bg=BG3, fg=FG, font=FONT_SMALL,
            height=7, relief=tk.FLAT, state=tk.DISABLED,
            highlightthickness=0, wrap=tk.WORD,
        )
        self._node_info.pack(fill=tk.X, padx=10, pady=(4, 0))

        ttk.Separator(side, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=10)

        # ---- Controls ---
        ctrl = tk.Frame(side, bg=BG2)
        ctrl.pack(fill=tk.X, padx=10)

        def _btn(text, cmd, col=BG3):
            b = tk.Button(ctrl, text=text, command=cmd,
                          bg=col, fg=FG, font=FONT_LABEL,
                          relief=tk.FLAT, padx=6, pady=3,
                          activebackground=ACCENT2, activeforeground=BG,
                          cursor="hand2")
            return b

        _btn("Обновить [R]", self._manual_refresh).pack(fill=tk.X, pady=2)
        _btn("Сбросить вид [Пробел]", self._reset_view).pack(fill=tk.X, pady=2)

        self._phys_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ctrl, text="Физика (авторасстановка)",
            variable=self._phys_var,
            bg=BG2, fg=FG, selectcolor=BG3,
            activebackground=BG2, activeforeground=FG,
            font=FONT_LABEL,
            command=lambda: setattr(self, "_physics_on", self._phys_var.get()),
        ).pack(anchor=tk.W, pady=(6, 2))

        self._label_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ctrl, text="Показывать подписи",
            variable=self._label_var,
            bg=BG2, fg=FG, selectcolor=BG3,
            activebackground=BG2, activeforeground=FG,
            font=FONT_LABEL,
        ).pack(anchor=tk.W)

        ttk.Separator(side, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=8)

        # Legend
        legend = tk.Frame(side, bg=BG2)
        legend.pack(fill=tk.X, padx=12, pady=(0, 12))
        tk.Label(legend, text="Легенда", bg=BG2, fg=FG_DIM,
                 font=FONT_SMALL).pack(anchor=tk.W)
        for color, text in (
            (ACCENT,  "Наш узел"),
            (GREEN,   "Активный пир"),
            (FG_DIM,  "Неактивный пир"),
            (RED,     "Проблема"),
        ):
            row = tk.Frame(legend, bg=BG2)
            row.pack(fill=tk.X, pady=1)
            tk.Canvas(row, bg=BG2, width=14, height=14,
                      highlightthickness=0).pack(side=tk.LEFT, padx=(0, 4))
            c = row.children[list(row.children)[-1]]
            c.create_oval(2, 2, 12, 12, fill=color, outline="")
            tk.Label(row, text=text, bg=BG2, fg=FG,
                     font=FONT_SMALL).pack(side=tk.LEFT)

    def _build_statusbar(self):
        self._statusbar = tk.Frame(self, bg=BG3, height=22)
        self._statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        self._statusbar.pack_propagate(False)

        self._status_lbl = tk.Label(
            self._statusbar, text="Инициализация…",
            bg=BG3, fg=FG_DIM, font=FONT_SMALL, anchor=tk.W,
        )
        self._status_lbl.pack(side=tk.LEFT, padx=8)

        self._time_lbl = tk.Label(
            self._statusbar, text="",
            bg=BG3, fg=FG_DIM, font=FONT_SMALL, anchor=tk.E,
        )
        self._time_lbl.pack(side=tk.RIGHT, padx=8)

    def _bind_keys(self):
        self.bind("<space>",  lambda _: self._reset_view())
        self.bind("<r>",      lambda _: self._manual_refresh())
        self.bind("<R>",      lambda _: self._manual_refresh())
        self.bind("<q>",      lambda _: self.destroy())
        self.bind("<Escape>", lambda _: self.destroy())
        self.bind("<plus>",   lambda _: self._zoom(1.15))
        self.bind("<minus>",  lambda _: self._zoom(0.87))

    # ------------------------------------------------------------------
    # Data polling
    # ------------------------------------------------------------------

    def _poll_loop(self):
        threading.Thread(target=self._fetch_data, daemon=True).start()
        self.after(self.POLL_INTERVAL, self._poll_loop)

    def _fetch_data(self):
        if self._demo:
            snap = _demo_snapshot(self._tick)
            self._tick += 1
        elif self._api:
            snap = self._api.get_snapshot()
        else:
            snap = None

        if snap:
            self._connected = True
            self._apply_snapshot(snap)
            self._last_update = time.time()
        else:
            self._connected = False

    def _apply_snapshot(self, snap: NetworkSnapshot):
        with self._lock:
            self._snap = snap
            new_addrs = {snap.local_address}
            for p in snap.peers:
                new_addrs.add(p["address"])

            # Spawn new nodes at random positions near centre
            cx = self._canvas.winfo_width()  / 2 or 400
            cy = self._canvas.winfo_height() / 2 or 300
            for addr in new_addrs:
                if addr not in self._nodes:
                    angle = random.uniform(0, 2*math.pi)
                    r = random.uniform(50, 120)
                    self._nodes[addr] = VizNode(
                        node_id  = addr[:10] + "…",
                        address  = addr,
                        x = cx + math.cos(angle) * r,
                        y = cy + math.sin(angle) * r,
                        is_local = (addr == snap.local_address),
                        color    = ACCENT if addr == snap.local_address else GREEN,
                    )

            # Remove nodes no longer seen
            for addr in list(self._nodes.keys()):
                if addr not in new_addrs:
                    del self._nodes[addr]

            # Update peer metadata
            for p in snap.peers:
                n = self._nodes.get(p["address"])
                if n:
                    n.ip   = p.get("ip", "?")
                    n.port = p.get("port", 0)
                    n.rtt  = float(p.get("rtt", 0))
                    n.color = GREEN if p.get("is_active", True) else FG_DIM

            # Update edges
            self._edges = [
                VizEdge(
                    src = snap.local_address,
                    dst = p["address"],
                    rtt = float(p.get("rtt", 0)),
                    active = p.get("is_active", True),
                )
                for p in snap.peers
            ]

    def _manual_refresh(self):
        threading.Thread(target=self._fetch_data, daemon=True).start()

    # ------------------------------------------------------------------
    # Coordinate transforms
    # ------------------------------------------------------------------

    def _world_to_screen(self, x: float, y: float) -> Tuple[int, int]:
        sx = int(x * self._scale + self._offset_x)
        sy = int(y * self._scale + self._offset_y)
        return sx, sy

    def _screen_to_world(self, sx: int, sy: int) -> Tuple[float, float]:
        x = (sx - self._offset_x) / self._scale
        y = (sy - self._offset_y) / self._scale
        return x, y

    def _node_at(self, sx: int, sy: int) -> Optional[str]:
        """Return address of the node under screen coordinate (sx, sy)."""
        for addr, n in self._nodes.items():
            nx, ny = self._world_to_screen(n.x, n.y)
            r = int(n.radius * self._scale) + 4
            if (sx - nx)**2 + (sy - ny)**2 <= r*r:
                return addr
        return None

    # ------------------------------------------------------------------
    # Mouse events
    # ------------------------------------------------------------------

    def _on_mouse_down(self, event):
        addr = self._node_at(event.x, event.y)
        if addr:
            self._drag_node = addr
            self._drag_start_x = event.x
            self._drag_start_y = event.y
            with self._lock:
                n = self._nodes.get(addr)
                if n:
                    n.pinned = True
            self._show_node_info(addr)
        else:
            self._panning = True
            self._pan_start_x = event.x
            self._pan_start_y = event.y

    def _on_mouse_drag(self, event):
        if self._drag_node:
            wx, wy = self._screen_to_world(event.x, event.y)
            with self._lock:
                n = self._nodes.get(self._drag_node)
                if n:
                    n.x, n.y = wx, wy
                    n.vx = n.vy = 0.0
        elif self._panning:
            dx = event.x - self._pan_start_x
            dy = event.y - self._pan_start_y
            self._offset_x += dx
            self._offset_y += dy
            self._pan_start_x = event.x
            self._pan_start_y = event.y

    def _on_mouse_up(self, event):
        if self._drag_node:
            with self._lock:
                n = self._nodes.get(self._drag_node)
                if n:
                    n.pinned = False
            self._drag_node = None
        self._panning = False

    def _on_right_click(self, event):
        addr = self._node_at(event.x, event.y)
        if addr:
            with self._lock:
                n = self._nodes.get(addr)
                if n:
                    n.pinned = not n.pinned

    def _on_scroll(self, event):
        factor = 1.1 if event.delta > 0 else 0.9
        self._zoom(factor, pivot=(event.x, event.y))

    def _on_hover(self, event):
        addr = self._node_at(event.x, event.y)
        self._hovered = addr
        if addr:
            self._canvas.configure(cursor="hand2")
        else:
            self._canvas.configure(cursor="fleur")

    def _zoom(self, factor: float, pivot: Optional[Tuple[int,int]] = None):
        if pivot is None:
            cx = self._canvas.winfo_width()  / 2
            cy = self._canvas.winfo_height() / 2
            pivot = (cx, cy)
        px, py = pivot
        self._offset_x = px - (px - self._offset_x) * factor
        self._offset_y = py - (py - self._offset_y) * factor
        self._scale   *= factor
        self._scale    = max(0.1, min(self._scale, 6.0))

    def _reset_view(self):
        """Centre view on the centroid of all nodes."""
        with self._lock:
            if not self._nodes:
                return
            xs = [n.x for n in self._nodes.values()]
            ys = [n.y for n in self._nodes.values()]
        cx_w = sum(xs) / len(xs)
        cy_w = sum(ys) / len(ys)
        cx_s = self._canvas.winfo_width()  / 2
        cy_s = self._canvas.winfo_height() / 2
        self._scale    = 1.0
        self._offset_x = cx_s - cx_w * self._scale
        self._offset_y = cy_s - cy_w * self._scale

    # ------------------------------------------------------------------
    # Sidebar info
    # ------------------------------------------------------------------

    def _show_node_info(self, addr: str):
        with self._lock:
            n = self._nodes.get(addr)
        if n is None:
            return
        lines = [
            f"{'[ЛОКАЛЬНЫЙ]' if n.is_local else '[Пир]'}",
            f"ID:   {n.node_id}",
            f"Addr: {n.address[:30]}",
            f"IP:   {n.ip}:{n.port}",
            f"RTT:  {n.rtt:.1f} ms" if n.rtt else "RTT:  —",
            f"Pin:  {'да' if n.pinned else 'нет'}",
        ]
        self._node_info.configure(state=tk.NORMAL)
        self._node_info.delete("1.0", tk.END)
        self._node_info.insert(tk.END, "\n".join(lines))
        self._node_info.configure(state=tk.DISABLED)

    def _update_stats(self):
        with self._lock:
            snap = self._snap
            n_nodes = len(self._nodes)
            n_edges = len(self._edges)
        if snap is None:
            return

        def _fmt_uptime(s: float) -> str:
            h, rem = divmod(int(s), 3600)
            m, sec = divmod(rem, 60)
            return f"{h:02d}:{m:02d}:{sec:02d}"

        self._stat_labels["Узлов"].configure(text=str(n_nodes))
        self._stat_labels["Соединений"].configure(text=str(n_edges))
        self._stat_labels["Аптайм"].configure(text=_fmt_uptime(snap.uptime))
        self._stat_labels["Отправлено"].configure(text=str(snap.messages_sent))
        self._stat_labels["Получено"].configure(text=str(snap.messages_received))

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _draw_loop(self):
        try:
            self._draw_frame()
        except tk.TclError:
            return   # window was destroyed
        self.after(self.FRAME_INTERVAL, self._draw_loop)

    def _draw_frame(self):
        c = self._canvas
        c.delete("all")

        w = c.winfo_width()
        h = c.winfo_height()
        if w < 2 or h < 2:
            return

        # Physics tick
        if self._physics_on and len(self._nodes) > 1:
            with self._lock:
                self._layout.tick(self._nodes, self._edges, dt=0.25)

        # ---- Background grid ----
        self._draw_grid(c, w, h)

        with self._lock:
            nodes = dict(self._nodes)
            edges = list(self._edges)
            snap  = self._snap

        # ---- Edges ----
        for e in edges:
            na = nodes.get(e.src)
            nb = nodes.get(e.dst)
            if na is None or nb is None:
                continue
            x1, y1 = self._world_to_screen(na.x, na.y)
            x2, y2 = self._world_to_screen(nb.x, nb.y)
            color = ACCENT if e.active else FG_DIM
            width = max(1, int(1.5 * self._scale))
            c.create_line(x1, y1, x2, y2,
                          fill=color, width=width,
                          dash=(4, 4) if not e.active else ())

            # RTT label on edge midpoint
            if e.rtt > 0 and self._label_var.get() and self._scale > 0.6:
                mx, my = (x1+x2)//2, (y1+y2)//2
                c.create_text(mx, my - 8, text=f"{e.rtt:.0f}ms",
                              fill=FG_DIM, font=FONT_SMALL)

        # ---- Nodes ----
        for addr, n in nodes.items():
            self._draw_node(c, n, addr == self._hovered)

        # ---- Status bar ----
        ts = datetime.now().strftime("%H:%M:%S")
        if self._connected or self._demo:
            ago = time.time() - self._last_update
            status = f"{'ДЕМО' if self._demo else 'ПОДКЛЮЧЕНО'}  ·  обновление {ago:.0f}с назад"
            self._status_lbl.configure(fg=GREEN, text=status)
        else:
            self._status_lbl.configure(
                fg=RED,
                text=f"Нет соединения с API — {self._api.base_url if self._api else '?'}"
            )
        self._time_lbl.configure(text=ts)
        self._update_stats()

    def _draw_grid(self, c: tk.Canvas, w: int, h: int):
        """Subtle dot-grid background."""
        spacing = max(30, int(40 * self._scale))
        ox = int(self._offset_x) % spacing
        oy = int(self._offset_y) % spacing
        for x in range(ox, w, spacing):
            for y in range(oy, h, spacing):
                c.create_oval(x-1, y-1, x+1, y+1, fill=BG3, outline="")

    def _draw_node(self, c: tk.Canvas, n: VizNode, hovered: bool):
        sx, sy = self._world_to_screen(n.x, n.y)
        r = int(n.radius * self._scale)
        if r < 4:
            return

        # Glow / halo for local node or hovered
        if n.is_local or hovered:
            hr = r + int(7 * self._scale)
            alpha_color = ACCENT if n.is_local else ACCENT2
            c.create_oval(sx-hr, sy-hr, sx+hr, sy+hr,
                          fill="", outline=alpha_color,
                          width=max(1, int(self._scale)))

        # Pinned indicator
        if n.pinned:
            c.create_oval(sx-r-3, sy-r-3, sx+r+3, sy+r+3,
                          fill="", outline=ORANGE, width=2)

        # Node circle
        outline = "white" if hovered else BG
        c.create_oval(sx-r, sy-r, sx+r, sy+r,
                      fill=n.color, outline=outline,
                      width=max(1, int(self._scale)))

        # Local node inner ring
        if n.is_local:
            ir = max(2, r - int(5 * self._scale))
            c.create_oval(sx-ir, sy-ir, sx+ir, sy+ir,
                          fill="", outline="white",
                          width=max(1, int(self._scale)))

        # Label
        if self._label_var.get() and self._scale > 0.45:
            short = n.node_id
            lbl_y = sy + r + max(6, int(8 * self._scale))
            c.create_text(sx, lbl_y, text=short,
                          fill=FG if not hovered else "white",
                          font=FONT_SMALL if self._scale < 1.5 else FONT_LABEL)

        # RTT badge on non-local nodes
        if not n.is_local and n.rtt > 0 and self._scale > 0.8:
            badge = f"{n.rtt:.0f}"
            c.create_text(sx, sy, text=badge,
                          fill="white", font=FONT_SMALL)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_viz",
        description="Murnet Network Visualizer — интерактивная карта топологии сети",
    )
    p.add_argument(
        "--api", metavar="URL",
        default="http://127.0.0.1:8080",
        help="URL REST API (по умолчанию: http://127.0.0.1:8080)",
    )
    p.add_argument(
        "--token", metavar="JWT",
        default="",
        help="Bearer-токен для авторизации в API",
    )
    p.add_argument(
        "--demo", action="store_true",
        help="Демо-режим — синтетическая сеть без живого узла",
    )
    p.add_argument(
        "--poll", type=int, default=3,
        help="Интервал опроса API в секундах (по умолчанию: 3)",
    )
    return p


def main():
    args = build_parser().parse_args()

    client: Optional[APIClient] = None
    if not args.demo:
        client = APIClient(args.api, token=args.token)
        # Quick reachability probe (non-blocking, just for first status)

    app = NetworkVisualizer(api_client=client, demo=args.demo)
    if args.poll:
        app.POLL_INTERVAL = args.poll * 1000
    app.mainloop()


if __name__ == "__main__":
    main()
