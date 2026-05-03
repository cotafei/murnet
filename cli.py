#!/usr/bin/env python3
"""
MurNet CLI v6.2 — interactive shell for a MurNet node.

Usage:
    python cli.py [--port PORT] [--data-dir DIR] [--api-port PORT] [--no-api]
"""

import argparse
import asyncio
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.prompt import Prompt
from rich.live import Live
from rich.spinner import Spinner
from rich.style import Style
from rich import box

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import HTML

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """[bold cyan]
 ███╗   ███╗██╗   ██╗██████╗ ███╗   ██╗███████╗████████╗
 ████╗ ████║██║   ██║██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
 ██╔████╔██║██║   ██║██████╔╝██╔██╗ ██║█████╗     ██║
 ██║╚██╔╝██║██║   ██║██╔══██╗██║╚██╗██║██╔══╝     ██║
 ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║ ╚████║███████╗   ██║
 ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝
[/bold cyan][dim]  v6.2  ·  Decentralized P2P Network  ·  X25519 + AES-256-GCM[/dim]"""

HELP_SECTIONS = {
    "Node": [
        ("status",              "Show node info and stats"),
        ("peers",               "List connected peers"),
        ("connect <ip> <port>", "Connect to a peer"),
        ("routes",              "Show routing table"),
        ("stop / start",        "Stop / restart the node"),
    ],
    "Messages": [
        ("send <addr> <text>",  "Send encrypted message"),
        ("inbox [--unread]",    "Show inbox (last 20)"),
    ],
    "DHT": [
        ("dht <key>",           "Look up value in DHT"),
        ("register <name>",     "Register Name Service alias"),
        ("lookup <name>",       "Resolve name → address"),
    ],
    "PubSub": [
        ("publish <topic> <text>",  "Publish object to topic"),
        ("subscribe <topic>",       "Live-subscribe to topic"),
        ("objects [<type>]",        "List local objects"),
    ],
    "Onion": [
        ("onion status",            "Relay entries + circuit stats"),
        ("onion relays",            "Known relays from directory"),
        ("onion connect <h1,h2,h3>","Build onion circuit"),
        ("onion send <text>",       "Send via active circuit"),
    ],
    "VPN": [
        ("vpn start [--config F]",  "Start SOCKS5 VPN proxy"),
        ("vpn stop",                "Stop VPN proxy"),
        ("vpn status",              "Active circuits and mode"),
    ],
    "Shell": [
        ("migrate",   "DB migration status"),
        ("clear",     "Clear screen"),
        ("help",      "Show this help"),
        ("quit",      "Exit"),
    ],
}

COMMANDS = [
    "help", "status", "peers", "connect", "send", "inbox",
    "register", "lookup", "dht", "routes", "migrate",
    "publish", "subscribe", "objects",
    "onion", "vpn",
    "start", "stop", "clear", "quit", "exit",
]


def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _addr(a: str, n: int = 14) -> str:
    return (a[:n] + "…") if len(a) > n else a


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

class MurnetCLI:
    def __init__(self, args: argparse.Namespace):
        self.args      = args
        self.node      = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._node_thread: Optional[threading.Thread] = None
        self._vpn_tunnel = None
        self._vpn_socks5: list = []
        # onion state
        self._onion_router    = None
        self._onion_transport = None
        self._onion_circuit   = None

    # ── node lifecycle ────────────────────────────────────────────────────────

    def _start_node_thread(self, password: str):
        self._loop = asyncio.new_event_loop()

        def _run():
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._async_start(password))
            self._loop.run_forever()

        self._node_thread = threading.Thread(target=_run, daemon=True, name="MurnetNode")
        self._node_thread.start()

        deadline = time.time() + 20
        with Live(Spinner("dots", text="[dim]Unlocking node (Argon2id)…[/dim]"),
                  console=console, refresh_per_second=12) as live:
            while self.node is None and time.time() < deadline:
                time.sleep(0.05)
            live.update("[green]Node ready.[/green]")

    async def _async_start(self, password: str):
        from core.node.async_node import AsyncMurnetNode
        from core.identity.keystore import WrongPasswordError
        try:
            self.node = AsyncMurnetNode(
                data_dir=self.args.data_dir,
                port=self.args.port,
                password=password,
            )
        except WrongPasswordError as exc:
            console.print(f"[bold red]Wrong password: {exc}[/bold red]")
            sys.exit(1)

        self.node.on_message_received = self._on_new_message
        await self.node.start()

        if not self.args.no_api:
            await self._start_api()

    async def _start_api(self):
        try:
            import uvicorn
            from api.server import create_app
            app    = create_app(self.node)
            config = uvicorn.Config(app, host="127.0.0.1",
                                    port=self.args.api_port, log_level="warning")
            asyncio.ensure_future(uvicorn.Server(config).serve())
            console.print(f"[dim]API → http://127.0.0.1:{self.args.api_port}[/dim]")
        except Exception as exc:
            console.print(f"[yellow]API disabled: {exc}[/yellow]")

    def _stop_node(self):
        if self._vpn_tunnel:
            self._vpn_stop()
        if self._loop and self.node:
            fut = asyncio.run_coroutine_threadsafe(self.node.stop(), self._loop)
            try:
                fut.result(timeout=5)
            except Exception:
                pass
        self.node = None

    def _call(self, coro):
        if not self._loop or not self.node:
            console.print("[red]Node is not running.[/red]")
            return None
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return fut.result(timeout=10)
        except Exception as exc:
            console.print(f"[red]Error:[/red] {exc}")
            return None

    # ── incoming messages ─────────────────────────────────────────────────────

    def _on_new_message(self, from_addr: str, to_addr: str, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        console.print(
            f"\n[bold cyan]  [{ts}] {_addr(from_addr)}[/bold cyan] "
            f"[white]{text}[/white]"
        )

    # ── commands ──────────────────────────────────────────────────────────────

    def cmd_help(self, _args):
        panels = []
        for section, cmds in HELP_SECTIONS.items():
            t = Table(show_header=False, box=None, padding=(0, 1))
            for name, desc in cmds:
                t.add_row(f"[bold cyan]{name}[/bold cyan]", f"[dim]{desc}[/dim]")
            panels.append(Panel(t, title=f"[bold]{section}[/bold]",
                                border_style="cyan", expand=False))
        console.print(Columns(panels, equal=False, expand=False))

    def cmd_status(self, _args):
        if not self.node:
            console.print("[red]Node not running.[/red]"); return
        st = self.node.get_status()
        t  = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        for k, v in st.items():
            t.add_row(f"[cyan]{k}[/cyan]", str(v))
        console.print(Panel(t, title="[bold]Node Status[/bold]",
                            border_style="green"))

    def cmd_peers(self, _args):
        if not self.node:
            return
        peers = self.node.get_peers()
        if not peers:
            console.print("[dim]No peers connected.[/dim]"); return
        t = Table("Address", "IP", "Port", "RTT ms", "Active",
                  box=box.SIMPLE, header_style="bold cyan")
        for p in peers:
            active = "[green]●[/green]" if p.get("is_active") else "[red]○[/red]"
            t.add_row(_addr(p["address"]), p["ip"], str(p["port"]),
                      str(p.get("rtt", "?")), active)
        console.print(t)

    def cmd_connect(self, args):
        if len(args) < 2:
            console.print("[yellow]Usage:[/yellow] connect <ip> <port>"); return
        ip, port = args[0], int(args[1])
        result = self._call(self.node.connect_to_peer(ip, port))
        icon   = "[green]✓[/green]" if result else "[red]✗[/red]"
        console.print(f"{icon} connect → {ip}:{port}")

    def cmd_send(self, args):
        if len(args) < 2:
            console.print("[yellow]Usage:[/yellow] send <address> <message…>"); return
        to_addr, text = args[0], " ".join(args[1:])
        msg_id = self._call(self.node.send_message(to_addr, text))
        if msg_id:
            console.print(f"[green]✓[/green] queued [dim]{msg_id[:12]}…[/dim]")
        else:
            console.print("[red]✗ failed to queue message[/red]")

    def cmd_inbox(self, args):
        if not self.node: return
        unread_only = "--unread" in args
        try:
            msgs = self.node.storage.get_messages(
                to_addr=self.node.address, limit=20, unread_only=unread_only)
        except Exception as exc:
            console.print(f"[red]Inbox error:[/red] {exc}"); return
        if not msgs:
            console.print("[dim]Inbox is empty.[/dim]"); return
        t = Table("Time", "From", "Message", box=box.SIMPLE, header_style="bold cyan")
        for m in msgs:
            mark    = "[bold cyan]*[/bold cyan]" if not m.get("read") else " "
            preview = (m.get("content_preview") or m.get("content") or "")[:60]
            t.add_row(mark + _ts(m.get("timestamp", 0)),
                      _addr(m.get("from_addr") or "?"),
                      preview)
        console.print(t)

    def cmd_routes(self, _args):
        try:
            table = self.node.routing.get_routing_table()
            t = Table("Destination", "Next Hop", "Cost", "Hops",
                      box=box.SIMPLE, header_style="bold cyan")
            for dest, info in (table or {}).items():
                t.add_row(_addr(dest), _addr(info.get("next_hop") or ""),
                          str(round(info.get("cost", 0), 2)),
                          str(info.get("hop_count", "?")))
            console.print(t)
        except Exception as exc:
            console.print(f"[red]Routes error:[/red] {exc}")

    def cmd_register(self, args):
        if not args:
            console.print("[yellow]Usage:[/yellow] register <name>"); return
        name = args[0]
        ok   = self.node.register_name(name)
        console.print(f"[green]✓[/green] registered '{name}'" if ok
                      else f"[red]✗ failed to register '{name}'[/red]")

    def cmd_lookup(self, args):
        if not args:
            console.print("[yellow]Usage:[/yellow] lookup <name>"); return
        addr = self.node.lookup_name(args[0])
        if addr:
            console.print(f"[cyan]{args[0]}[/cyan] → [green]{addr}[/green]")
        else:
            console.print(f"[yellow]'{args[0]}' not found in DHT.[/yellow]")

    def cmd_dht(self, args):
        if not args:
            console.print("[yellow]Usage:[/yellow] dht <key>"); return
        try:
            val = self.node.murnaked.get(args[0])
            console.print(f"[cyan]DHT[{args[0]}][/cyan] = {val}")
        except Exception as exc:
            console.print(f"[red]DHT error:[/red] {exc}")

    def cmd_publish(self, args):
        if len(args) < 2:
            console.print("[yellow]Usage:[/yellow] publish <topic> <text…>"); return
        topic, text = args[0], " ".join(args[1:])
        if not self.node: return
        from core.data.objects import MurObject
        from core.identity.identity import NodeIdentity
        identity = NodeIdentity(private_key_bytes=self.node.identity.to_bytes())
        obj = MurObject.create(obj_type="text", owner=self.node.address,
                               data={"text": text, "topic": topic}, identity=identity)
        self._call(self.node.pubsub.async_publish(topic, obj))
        console.print(f"[green]✓[/green] published [dim]{obj.id[:12]}…[/dim]"
                      f" → topic [cyan]{topic}[/cyan]")

    def cmd_subscribe(self, args):
        if not args:
            console.print("[yellow]Usage:[/yellow] subscribe <topic>"); return
        topic = args[0]
        if not self.node: return

        def _on_obj(tid, obj):
            ts   = datetime.now().strftime("%H:%M:%S")
            text = obj.data.get("text", str(obj.data))
            console.print(f"\n[bold green]  [{ts}] [{topic}][/bold green]"
                          f" [cyan]{_addr(obj.owner)}[/cyan]"
                          f" [white]{text}[/white]")

        self.node.pubsub.subscribe(topic, _on_obj)
        console.print(f"[green]✓[/green] subscribed to [cyan]{topic}[/cyan]"
                      f"  [dim](messages will appear live)[/dim]")

    def cmd_objects(self, args):
        if not self.node: return
        obj_type = args[0] if args else None
        store    = self.node.object_store
        objs     = (store.list_by_type(obj_type) if obj_type
                    else [store.get(oid) for oid in store.list_ids()])
        objs     = [o for o in objs if o is not None]
        if not objs:
            console.print("[dim]No objects stored locally.[/dim]"); return
        t = Table("ID", "Type", "Owner", "Time", box=box.SIMPLE, header_style="bold cyan")
        for o in objs:
            ts = datetime.fromtimestamp(o.timestamp).strftime("%m-%d %H:%M")
            t.add_row(f"[dim]{_addr(o.id, 16)}[/dim]",
                      f"[cyan]{o.type}[/cyan]", _addr(o.owner), ts)
        console.print(t)

    def cmd_migrate(self, _args):
        from core.data.migrations import status as migration_status
        import sqlite3
        db_path = os.path.join(self.args.data_dir, "murnet.db")
        if not os.path.exists(db_path):
            console.print("[dim]Database does not exist yet.[/dim]"); return
        conn = sqlite3.connect(db_path)
        try:
            st = migration_status(conn)
        finally:
            conn.close()
        t = Table(show_header=False, box=box.SIMPLE)
        for k, v in st.items():
            val = ("[green]yes[/green]" if v is True else
                   "[red]no[/red]"      if v is False else str(v))
            t.add_row(f"[cyan]{k}[/cyan]", val)
        console.print(Panel(t, title="[bold]DB Migrations[/bold]", border_style="cyan"))

    # ── onion commands ────────────────────────────────────────────────────────

    def cmd_onion(self, args):
        sub = (args[0].lower() if args else "status")
        if sub == "status":
            self._onion_status()
        elif sub == "relays":
            self._onion_relays()
        elif sub == "connect":
            self._onion_connect(args[1:])
        elif sub == "send":
            self._onion_send(args[1:])
        else:
            console.print(f"[yellow]Usage:[/yellow] onion status|relays|connect|send")

    def _onion_status(self):
        r = self._onion_router
        tr = self._onion_transport
        t  = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        t.add_row("[cyan]router[/cyan]",
                  f"[green]{r.addr}[/green]" if r else "[red]not started[/red]")
        if tr:
            t.add_row("[cyan]relay_entries[/cyan]", str(len(r._relays)))
            t.add_row("[cyan]dir_relays[/cyan]",    str(len(tr.directory)))
            t.add_row("[cyan]connections_out[/cyan]", str(len(tr._out)))
            t.add_row("[cyan]connections_in[/cyan]",  str(len(tr._inc)))
        t.add_row("[cyan]circuit[/cyan]",
                  f"[green]{self._onion_circuit.depth}-hop active[/green]"
                  if self._onion_circuit else "[dim]none[/dim]")
        console.print(Panel(t, title="[bold]Onion Router[/bold]",
                            border_style="magenta"))

    def _onion_relays(self):
        if not self._onion_transport:
            console.print("[dim]Onion transport not running.[/dim]"); return
        relays = self._onion_transport.directory.alive()
        if not relays:
            console.print("[dim]No relays discovered yet. Start with --announce relays first.[/dim]")
            return
        t = Table("Name", "Address", "Age s", box=box.SIMPLE, header_style="bold cyan")
        now = time.time()
        for r in relays:
            age = int(now - r.timestamp)
            t.add_row(f"[cyan]{r.name}[/cyan]", r.addr, str(age))
        console.print(t)

    def _onion_connect(self, args):
        if not args:
            console.print("[yellow]Usage:[/yellow] onion connect <hop1,hop2,hop3>"); return
        if not self._onion_router:
            console.print("[yellow]Start an onion router first (not integrated with full node yet).[/yellow]")
            return
        hops = [h.strip() for h in args[0].split(",")]
        resolved = [self._onion_transport.resolve(h) for h in hops]

        async def _build():
            self._onion_circuit = await self._onion_router.build_circuit(resolved)
            return self._onion_circuit

        c = self._call(_build())
        if c:
            path = " → ".join(hops)
            console.print(f"[green]✓[/green] circuit built: [cyan]{path}[/cyan]"
                          f" ([dim]{c.depth} hops[/dim])")
        else:
            console.print("[red]✗ circuit build failed[/red]")

    def _onion_send(self, args):
        if not args:
            console.print("[yellow]Usage:[/yellow] onion send <text…>"); return
        if not self._onion_circuit:
            console.print("[yellow]Build a circuit first: onion connect <hops>[/yellow]"); return
        text    = " ".join(args)
        payload = text.encode()

        async def _send():
            await self._onion_router.send_data(self._onion_circuit, "cli", payload)

        self._call(_send())
        console.print(f"[green]✓[/green] sent via {self._onion_circuit.depth}-hop circuit")

    # ── vpn commands ──────────────────────────────────────────────────────────

    def cmd_vpn(self, args):
        if not args:
            console.print("[yellow]Usage:[/yellow] vpn start|stop|status"); return
        sub = args[0].lower()
        if sub == "start":   self._vpn_start(args[1:])
        elif sub == "stop":  self._vpn_stop()
        elif sub == "status":self._vpn_status()
        else:
            console.print(f"[yellow]Unknown vpn subcommand:[/yellow] '{sub}'")

    def _vpn_start(self, extra_args: list):
        if self._vpn_tunnel:
            console.print("[yellow]VPN already running. Use 'vpn stop' first.[/yellow]"); return
        if not self.node:
            console.print("[red]Node is not running.[/red]"); return

        config_path = "configs/vpn_client.json"
        try:
            idx = extra_args.index("--config")
            config_path = extra_args[idx + 1]
        except (ValueError, IndexError):
            pass

        if not Path(config_path).exists():
            console.print(f"[red]Config not found:[/red] {config_path}"); return

        from core.vpn.config import VPNConfig
        from core.vpn.tunnel import TunnelManager
        from core.vpn.socks5 import Socks5Server

        try:
            vpn_cfg = VPNConfig.load(config_path)
        except Exception as exc:
            console.print(f"[red]Config error:[/red] {exc}"); return

        exit_peer = None

        async def _start():
            nonlocal exit_peer
            loop = asyncio.get_event_loop()
            for ob in vpn_cfg.outbounds:
                if ob.protocol == "murnet":
                    for peer in ob.murnet_peers():
                        console.print(f"[dim]Connecting to {peer.address}:{peer.port}…[/dim]")
                        await self.node.connect_to_peer(peer.address, peer.port)
                        await asyncio.sleep(1.5)
                        exit_peer = peer.id or next(
                            (p["address"] for p in self.node.get_peers()
                             if p.get("ip") == peer.address), None)
                    break

            tunnel = TunnelManager(self.node, exit_peer=exit_peer,
                                   exit_mode=vpn_cfg.exit_mode)
            await tunnel.start(loop)
            self._vpn_tunnel = tunnel
            self._vpn_socks5 = []
            for inbound in vpn_cfg.inbounds:
                if inbound.protocol == "socks":
                    srv = Socks5Server(tunnel, inbound.listen, inbound.port)
                    await srv.start()
                    self._vpn_socks5.append(srv)

        self._call(_start())

        if self._vpn_tunnel:
            mode = "exit" if vpn_cfg.exit_mode else "client"
            t = Table(show_header=False, box=box.SIMPLE)
            t.add_row("[cyan]mode[/cyan]",      mode)
            t.add_row("[cyan]exit_peer[/cyan]",  (exit_peer or "—")[:32])
            for srv in self._vpn_socks5:
                t.add_row("[cyan]socks5[/cyan]", f"{srv.listen}:{srv.port}")
            console.print(Panel(t, title="[bold]VPN Started[/bold]",
                                border_style="green"))
        else:
            console.print("[red]✗ VPN failed to start[/red]")

    def _vpn_stop(self):
        if not self._vpn_tunnel:
            console.print("[dim]VPN is not running.[/dim]"); return

        async def _stop():
            for srv in self._vpn_socks5:
                await srv.stop()
            self._vpn_socks5.clear()
            self._vpn_tunnel.stop()
            self._vpn_tunnel = None

        self._call(_stop())
        console.print("[yellow]VPN stopped.[/yellow]")

    def _vpn_status(self):
        if not self._vpn_tunnel:
            console.print("[dim]VPN is not running.[/dim]"); return
        tunnel   = self._vpn_tunnel
        circuits = list(tunnel._circuits.values())
        mode     = ("exit+client" if tunnel.exit_mode and tunnel.exit_peer
                    else "exit" if tunnel.exit_mode else "client")
        t = Table(show_header=False, box=box.SIMPLE)
        t.add_row("[cyan]mode[/cyan]",             mode)
        t.add_row("[cyan]exit_peer[/cyan]",         (tunnel.exit_peer or "—")[:32])
        t.add_row("[cyan]active_circuits[/cyan]",   str(len(circuits)))
        t.add_row("[cyan]socks5_listeners[/cyan]",  str(len(self._vpn_socks5)))
        console.print(Panel(t, title="[bold]VPN Status[/bold]",
                            border_style="magenta"))
        if circuits:
            ct = Table("Circuit", "State", "Destination",
                       box=box.SIMPLE, header_style="bold cyan")
            for c in circuits:
                ct.add_row(f"[dim]{c.id[:12]}…[/dim]",
                           f"[green]{c.state.value}[/green]"
                           if c.state.value == "CONNECTED" else c.state.value,
                           f"{c.dst_host}:{c.dst_port}")
            console.print(ct)

    # ── REPL ──────────────────────────────────────────────────────────────────

    def _banner(self):
        addr   = getattr(self.node, "address", "initializing…")
        port   = self.args.port
        api    = ("disabled" if self.args.no_api
                  else f"http://127.0.0.1:{self.args.api_port}")
        footer = (f"[dim]addr:[/dim] [cyan]{addr}[/cyan]   "
                  f"[dim]port:[/dim] [cyan]{port}[/cyan]   "
                  f"[dim]api:[/dim] [cyan]{api}[/cyan]   "
                  f"[dim]type [bold]help[/bold] for commands[/dim]")
        console.print(Panel(BANNER + "\n\n" + footer,
                            border_style="cyan", expand=False))

    def _prompt_text(self) -> HTML:
        addr  = (self.node.address[:8] + "…") if self.node else "offline"
        state = "●" if self.node else "○"
        color = "ansicyan" if self.node else "ansired"
        return HTML(f'<{color}>{state} murnet</{color}> '
                    f'<ansiwhite>({addr})</ansiwhite>'
                    f'<ansibrightblack> ❯ </ansibrightblack>')

    def run(self):
        from core.identity.keystore import prompt_password_cli
        password = prompt_password_cli(self.args.data_dir)
        self._start_node_thread(password)
        self._banner()

        history_file = os.path.join(self.args.data_dir, ".cli_history")
        os.makedirs(self.args.data_dir, exist_ok=True)

        session = PromptSession(
            history=FileHistory(history_file),
            auto_suggest=AutoSuggestFromHistory(),
            completer=WordCompleter(COMMANDS, ignore_case=True),
        )

        while True:
            try:
                with patch_stdout():
                    line = session.prompt(self._prompt_text).strip()
            except (EOFError, KeyboardInterrupt):
                console.print()
                break

            if not line:
                continue

            parts = line.split()
            cmd   = parts[0].lower()
            args  = parts[1:]

            dispatch = {
                "help":      self.cmd_help,
                "status":    self.cmd_status,
                "peers":     self.cmd_peers,
                "connect":   self.cmd_connect,
                "send":      self.cmd_send,
                "inbox":     self.cmd_inbox,
                "register":  self.cmd_register,
                "lookup":    self.cmd_lookup,
                "dht":       self.cmd_dht,
                "routes":    self.cmd_routes,
                "migrate":   self.cmd_migrate,
                "publish":   self.cmd_publish,
                "subscribe": self.cmd_subscribe,
                "objects":   self.cmd_objects,
                "onion":     self.cmd_onion,
                "vpn":       self.cmd_vpn,
            }

            if cmd in ("quit", "exit"):
                break
            elif cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
            elif cmd == "stop":
                self._stop_node()
                console.print("[yellow]Node stopped.[/yellow]")
            elif cmd == "start":
                if not self.node:
                    pw = prompt_password_cli(self.args.data_dir)
                    self._start_node_thread(pw)
                    console.print("[green]Node started.[/green]")
                else:
                    console.print("[dim]Already running.[/dim]")
            elif cmd in dispatch:
                dispatch[cmd](args)
            else:
                console.print(f"[yellow]Unknown command:[/yellow] '{cmd}'  "
                              f"[dim](type help)[/dim]")

        console.print("\n[dim]Shutting down…[/dim]")
        self._stop_node()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="murnet",
                                description="MurNet v6.2 — Async P2P node CLI")
    p.add_argument("--port",      type=int, default=8888,     help="P2P UDP port")
    p.add_argument("--api-port",  type=int, default=8080,     help="REST API port")
    p.add_argument("--data-dir",  type=str, default="./data", help="Data directory")
    p.add_argument("--no-api",    action="store_true",        help="Disable REST API")
    p.add_argument("--log-level", type=str, default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def main():
    import logging
    args = build_parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    MurnetCLI(args).run()


if __name__ == "__main__":
    main()
