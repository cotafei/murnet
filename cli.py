#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET CLI v6.2
Async-aware interactive shell for managing a Murnet node.

Usage:
    python cli.py [--port PORT] [--data-dir DIR] [--api-port PORT] [--no-api]
"""

import argparse
import asyncio
import os
import sys
import signal
import time
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

# ---------------------------------------------------------------------------
# Optional rich / prompt_toolkit
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.patch_stdout import patch_stdout
    HAS_PTOOLKIT = True
except ImportError:
    HAS_PTOOLKIT = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


class SimpleConsole:
    """Fallback when rich is not available."""
    def print(self, *args, **kwargs):
        print(*args)
    def rule(self, title=""):
        print(f"--- {title} ---")


if HAS_RICH:
    console = Console()
else:
    console = SimpleConsole()


# ---------------------------------------------------------------------------
# MurnetCLI
# ---------------------------------------------------------------------------

COMMANDS = [
    "help", "status", "peers", "connect", "send", "inbox",
    "register", "lookup", "dht", "routes", "migrate",
    "publish", "subscribe", "objects",
    "vpn",
    "start", "stop", "restart", "clear", "quit", "exit",
]

HELP_TEXT = """\
  status                    — Show node status
  peers                     — List connected peers
  connect <ip> <port>       — Connect to a peer
  send <addr> <text>        — Send a message
  inbox [--unread]          — Show inbox (default: last 20)
  register <name>           — Register a Name Service alias
  lookup <name>             — Resolve name -> address
  dht <key>                 — Look up DHT key
  routes                    — Show routing table
  migrate                   — Show DB migration status

  publish <topic> <text>    — Publish a text object to a topic (v6.2)
  subscribe <topic>         — Subscribe to a topic (prints live updates)
  objects [<type>]          — List locally stored objects

  vpn start [--config PATH] — Start VPN proxy (SOCKS5 inbound)
  vpn stop                  — Stop VPN proxy
  vpn status                — Show VPN circuits and stats

  stop / start              — Stop / start the node
  clear                     — Clear screen
  quit / exit               — Exit CLI
"""


class MurnetCLI:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.node = None
        self.api_server = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._node_thread: Optional[threading.Thread] = None
        # VPN state
        self._vpn_tunnel = None
        self._vpn_socks5: list = []

    # ------------------------------------------------------------------
    # Node lifecycle (runs in background thread with its own event loop)
    # ------------------------------------------------------------------

    def _start_node_thread(self, password: str):
        """Start the async node in a background thread."""
        self._loop = asyncio.new_event_loop()

        def _run():
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._async_start(password))
            self._loop.run_forever()

        self._node_thread = threading.Thread(target=_run, daemon=True, name="MurnetNode")
        self._node_thread.start()

        # Wait until the node is ready (up to 15 s — Argon2id derivation ~1-3s)
        deadline = time.time() + 15
        while self.node is None and time.time() < deadline:
            time.sleep(0.05)

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
            if HAS_RICH:
                console.print(f"[bold red]ОШИБКА: {exc}[/bold red]")
            else:
                print(f"ОШИБКА: {exc}")
            import sys
            sys.exit(1)

        self.node.on_message_received = self._on_new_message
        await self.node.start()

        if not self.args.no_api:
            await self._start_api()

    async def _start_api(self):
        try:
            import uvicorn
            from api.server import create_app
            app = create_app(self.node)
            config = uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.args.api_port,
                log_level="warning",
            )
            server = uvicorn.Server(config)
            asyncio.ensure_future(server.serve())
            console.print(f"[green]API server: http://127.0.0.1:{self.args.api_port}[/green]"
                          if HAS_RICH else
                          f"API server: http://127.0.0.1:{self.args.api_port}")
        except Exception as exc:
            console.print(f"[yellow]API not started: {exc}[/yellow]" if HAS_RICH else f"API not started: {exc}")

    def _stop_node(self):
        if self._vpn_tunnel is not None:
            self._vpn_stop()
        if self._loop and self.node:
            future = asyncio.run_coroutine_threadsafe(self.node.stop(), self._loop)
            try:
                future.result(timeout=5)
            except Exception:
                pass
        self.node = None

    def _node_call(self, coro):
        """Run a coroutine in the node's event loop and return result."""
        if not self._loop or not self.node:
            return None
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=10)
        except Exception as exc:
            console.print(f"Error: {exc}")
            return None

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_new_message(self, from_addr: str, to_addr: str, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        msg = f"\n[{ts}] New message from {from_addr[:12]}…: {text}"
        if HAS_RICH:
            console.print(f"[bold cyan]{msg}[/bold cyan]")
        else:
            print(msg)

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def cmd_status(self, _args):
        if not self.node:
            console.print("Node not running." if not HAS_RICH else "[red]Node not running.[/red]")
            return
        st = self.node.get_status()
        if HAS_RICH:
            t = Table(show_header=False, box=box.SIMPLE)
            for k, v in st.items():
                t.add_row(f"[cyan]{k}[/cyan]", str(v))
            console.print(Panel(t, title="Node Status", border_style="green"))
        else:
            for k, v in st.items():
                print(f"  {k}: {v}")

    def cmd_peers(self, _args):
        if not self.node:
            return
        peers = self.node.get_peers()
        if not peers:
            console.print("No peers connected.")
            return
        if HAS_RICH:
            t = Table("Address", "IP", "Port", "RTT ms", "Active", box=box.SIMPLE)
            for p in peers:
                t.add_row(
                    p["address"][:16] + "…",
                    p["ip"],
                    str(p["port"]),
                    str(p.get("rtt", "?")),
                    "[green]yes[/green]" if p.get("is_active") else "[red]no[/red]",
                )
            console.print(t)
        else:
            for p in peers:
                print(f"  {p['address'][:16]}… {p['ip']}:{p['port']} rtt={p.get('rtt', '?')}ms")

    def cmd_connect(self, args):
        if len(args) < 2:
            console.print("Usage: connect <ip> <port>")
            return
        ip, port = args[0], int(args[1])
        result = self._node_call(self.node.connect_to_peer(ip, port))
        console.print(f"Connect {'OK' if result else 'FAILED'} → {ip}:{port}")

    def cmd_send(self, args):
        if len(args) < 2:
            console.print("Usage: send <address> <message text...>")
            return
        to_addr = args[0]
        text = " ".join(args[1:])
        msg_id = self._node_call(self.node.send_message(to_addr, text))
        if msg_id:
            console.print(f"Queued: {msg_id[:8]}…")
        else:
            console.print("Failed to queue message." if not HAS_RICH else "[red]Failed to queue message.[/red]")

    def cmd_inbox(self, args):
        if not self.node:
            return
        limit = 20
        unread_only = "--unread" in args
        try:
            msgs = self.node.storage.get_messages(
                to_addr=self.node.address,
                limit=limit,
                unread_only=unread_only,
            )
        except Exception as exc:
            console.print(f"Error reading inbox: {exc}")
            return
        if not msgs:
            console.print("Inbox is empty.")
            return
        for m in msgs:
            ts = _ts(m.get("timestamp", 0))
            frm = (m.get("from_addr") or "?")[:16]
            preview = (m.get("content_preview") or m.get("content") or "")[:60]
            read_mark = " " if m.get("read") else "*"
            print(f"  [{ts}]{read_mark}{frm}… : {preview}")

    def cmd_register(self, args):
        if not args:
            console.print("Usage: register <name>")
            return
        name = args[0]
        ok = self.node.register_name(name)
        console.print(f"Registered '{name}'" if ok else f"Failed to register '{name}'")

    def cmd_lookup(self, args):
        if not args:
            console.print("Usage: lookup <name>")
            return
        addr = self.node.lookup_name(args[0])
        if addr:
            console.print(f"{args[0]} → {addr}")
        else:
            console.print(f"'{args[0]}' not found in DHT.")

    def cmd_dht(self, args):
        if not args:
            console.print("Usage: dht <key>")
            return
        key = args[0]
        try:
            val = self.node.murnaked.get(key)
            console.print(f"DHT[{key}] = {val}")
        except Exception as exc:
            console.print(f"DHT error: {exc}")

    def cmd_routes(self, _args):
        try:
            table = self.node.routing.get_routing_table()
            if HAS_RICH:
                t = Table("Destination", "Next Hop", "Cost", "Hops", box=box.SIMPLE)
                for dest, info in (table or {}).items():
                    t.add_row(
                        dest[:16] + "…",
                        (info.get("next_hop") or "")[:16] + "…",
                        str(round(info.get("cost", 0), 2)),
                        str(info.get("hop_count", "?")),
                    )
                console.print(t)
            else:
                for dest, info in (table or {}).items():
                    print(f"  {dest[:16]}… via {(info.get('next_hop') or '')[:16]}… cost={info.get('cost', 0)}")
        except Exception as exc:
            console.print(f"Routes error: {exc}")

    def cmd_publish(self, args):
        """publish <topic> <text...>  — create and gossip a text object."""
        if len(args) < 2:
            console.print("Usage: publish <topic> <text...>")
            return
        topic = args[0]
        text = " ".join(args[1:])
        if not self.node:
            return
        from core.data.objects import MurObject
        from core.identity.identity import NodeIdentity
        identity = NodeIdentity(private_key_bytes=self.node.identity.to_bytes())
        obj = MurObject.create(
            obj_type="text",
            owner=self.node.address,
            data={"text": text, "topic": topic},
            identity=identity,
        )

        async def _pub():
            await self.node.pubsub.async_publish(topic, obj)

        self._node_call(_pub())
        console.print(f"Published object {obj.id[:12]}... to topic '{topic}'")

    def cmd_subscribe(self, args):
        """subscribe <topic>  — register a console callback for arriving objects."""
        if not args:
            console.print("Usage: subscribe <topic>")
            return
        topic = args[0]
        if not self.node:
            return

        def _on_obj(tid, obj):
            ts = datetime.now().strftime("%H:%M:%S")
            text = obj.data.get("text", obj.data)
            msg = f"\n[{ts}] [{topic}] {obj.owner[:12]}…: {text}"
            if HAS_RICH:
                console.print(f"[bold green]{msg}[/bold green]")
            else:
                print(msg)

        self.node.pubsub.subscribe(topic, _on_obj)
        console.print(f"Subscribed to topic '{topic}'.")

    def cmd_objects(self, args):
        """objects [<type>]  — list locally stored objects."""
        if not self.node:
            return
        obj_type = args[0] if args else None
        store = self.node.object_store
        if obj_type:
            objs = store.list_by_type(obj_type)
        else:
            objs = [store.get(oid) for oid in store.list_ids()]
            objs = [o for o in objs if o is not None]

        if not objs:
            console.print("No objects stored locally.")
            return

        if HAS_RICH:
            from rich.table import Table
            from rich import box
            t = Table("ID", "Type", "Owner", "Timestamp", box=box.SIMPLE)
            for o in objs:
                import datetime as _dt
                ts = _dt.datetime.fromtimestamp(o.timestamp).strftime("%Y-%m-%d %H:%M:%S")
                t.add_row(o.id[:14] + "…", o.type, o.owner[:14] + "…", ts)
            console.print(t)
        else:
            for o in objs:
                print(f"  {o.id[:14]}… type={o.type} owner={o.owner[:14]}…")

    def cmd_vpn(self, args):
        if not args:
            console.print("Usage: vpn start|stop|status [--config <path>]")
            return
        sub = args[0].lower()
        if sub == "start":
            self._vpn_start(args[1:])
        elif sub == "stop":
            self._vpn_stop()
        elif sub == "status":
            self._vpn_status()
        else:
            console.print(f"Unknown vpn subcommand: '{sub}'. Use start|stop|status")

    def _vpn_start(self, extra_args: list):
        if self._vpn_tunnel is not None:
            console.print("VPN already running. Use 'vpn stop' first.")
            return
        if not self.node:
            console.print("Node is not running. Start the node first.")
            return

        config_path = "configs/vpn_client.json"
        try:
            idx = extra_args.index("--config")
            config_path = extra_args[idx + 1]
        except (ValueError, IndexError):
            pass

        if not Path(config_path).exists():
            console.print(f"Config not found: {config_path}")
            console.print("Tip: edit configs/vpn_client.json with your exit node details.")
            return

        from core.vpn.config import VPNConfig
        from core.vpn.tunnel import TunnelManager
        from core.vpn.socks5 import Socks5Server

        try:
            vpn_cfg = VPNConfig.load(config_path)
        except Exception as exc:
            console.print(f"Failed to load VPN config: {exc}")
            return

        async def _start():
            loop = asyncio.get_event_loop()
            exit_peer = None

            # Connect to murnet exit peers
            for ob in vpn_cfg.outbounds:
                if ob.protocol == "murnet":
                    for peer in ob.murnet_peers():
                        console.print(f"Connecting to exit peer {peer.address}:{peer.port}…"
                                      if not HAS_RICH else
                                      f"[dim]Connecting to exit peer {peer.address}:{peer.port}…[/dim]")
                        await self.node.connect_to_peer(peer.address, peer.port)
                        await asyncio.sleep(1.5)
                        if peer.id:
                            exit_peer = peer.id
                        else:
                            for p in self.node.get_peers():
                                if p.get("ip") == peer.address:
                                    exit_peer = p["address"]
                                    break
                    break

            tunnel = TunnelManager(
                node=self.node,
                exit_peer=exit_peer,
                exit_mode=vpn_cfg.exit_mode,
            )
            await tunnel.start(loop)
            self._vpn_tunnel = tunnel

            self._vpn_socks5 = []
            for inbound in vpn_cfg.inbounds:
                if inbound.protocol == "socks":
                    srv = Socks5Server(tunnel, inbound.listen, inbound.port)
                    await srv.start()
                    self._vpn_socks5.append(srv)

        self._node_call(_start())

        if self._vpn_tunnel is not None:
            mode = "exit" if vpn_cfg.exit_mode else "client"
            lines = [f"VPN started ({mode} mode)"]
            for srv in self._vpn_socks5:
                lines.append(f"  SOCKS5 proxy → {srv.listen}:{srv.port}")
            if exit_peer if 'exit_peer' in dir() else False:
                pass
            msg = "\n".join(lines)
            console.print(f"[green]{msg}[/green]" if HAS_RICH else msg)
        else:
            console.print("[red]VPN failed to start.[/red]" if HAS_RICH else "VPN failed to start.")

    def _vpn_stop(self):
        if self._vpn_tunnel is None:
            console.print("VPN is not running.")
            return

        async def _stop():
            for srv in self._vpn_socks5:
                await srv.stop()
            self._vpn_socks5.clear()
            self._vpn_tunnel.stop()
            self._vpn_tunnel = None

        self._node_call(_stop())
        console.print("[yellow]VPN stopped.[/yellow]" if HAS_RICH else "VPN stopped.")

    def _vpn_status(self):
        if self._vpn_tunnel is None:
            console.print("[dim]VPN is not running.[/dim]" if HAS_RICH else "VPN is not running.")
            return

        tunnel = self._vpn_tunnel
        circuits = list(tunnel._circuits.values())
        mode = ("exit+client" if (tunnel.exit_mode and tunnel.exit_peer)
                else ("exit" if tunnel.exit_mode else "client"))

        if HAS_RICH:
            t = Table(show_header=False, box=box.SIMPLE)
            t.add_row("[cyan]mode[/cyan]", mode)
            t.add_row("[cyan]exit_peer[/cyan]", (tunnel.exit_peer or "—")[:32])
            t.add_row("[cyan]active_circuits[/cyan]", str(len(circuits)))
            t.add_row("[cyan]socks5_listeners[/cyan]", str(len(self._vpn_socks5)))
            console.print(Panel(t, title="VPN Status", border_style="magenta"))
            if circuits:
                ct = Table("Circuit", "State", "Destination", box=box.SIMPLE)
                for c in circuits:
                    ct.add_row(c.id[:12] + "…", c.state.value,
                               f"{c.dst_host}:{c.dst_port}")
                console.print(ct)
        else:
            print(f"  mode: {mode}")
            print(f"  exit_peer: {(tunnel.exit_peer or '—')[:32]}")
            print(f"  active_circuits: {len(circuits)}")
            for srv in self._vpn_socks5:
                print(f"  socks5: {srv.listen}:{srv.port}")
            for c in circuits:
                print(f"    {c.id[:12]}… {c.state.value} → {c.dst_host}:{c.dst_port}")

    def cmd_migrate(self, _args):
        from core.data.migrations import status as migration_status
        import sqlite3
        db_path = os.path.join(self.args.data_dir, "murnet.db")
        if not os.path.exists(db_path):
            console.print("Database does not exist yet.")
            return
        conn = sqlite3.connect(db_path)
        try:
            st = migration_status(conn)
        finally:
            conn.close()
        if HAS_RICH:
            t = Table(show_header=False, box=box.SIMPLE)
            t.add_row("[cyan]current_version[/cyan]", str(st["current_version"]))
            t.add_row("[cyan]latest_version[/cyan]", str(st["latest_version"]))
            t.add_row("[cyan]up_to_date[/cyan]", "[green]yes[/green]" if st["is_up_to_date"] else "[red]no[/red]")
            t.add_row("[cyan]applied[/cyan]", str(st["applied"]))
            t.add_row("[cyan]pending[/cyan]", str(st["pending"]))
            console.print(Panel(t, title="DB Migrations", border_style="cyan"))
        else:
            for k, v in st.items():
                print(f"  {k}: {v}")

    # ------------------------------------------------------------------
    # REPL
    # ------------------------------------------------------------------

    def _banner(self):
        if HAS_RICH:
            console.print(Panel(
                "[bold cyan]Murnet v6.2[/bold cyan]  |  Async P2P Node\n"
                f"[dim]Address:[/dim] {getattr(self.node, 'address', 'initializing…')}\n"
                "[dim]Type [bold]help[/bold] for available commands.[/dim]",
                border_style="cyan",
            ))
        else:
            print("=" * 50)
            print("  Murnet v6.2 — Async P2P Node")
            addr = getattr(self.node, "address", "initializing…")
            print(f"  Address: {addr}")
            print("  Type 'help' for commands.")
            print("=" * 50)

    def run(self):
        """Start node and enter the interactive REPL."""
        from core.identity.keystore import prompt_password_cli
        password = prompt_password_cli(self.args.data_dir)

        if HAS_RICH:
            console.print("[dim]Разблокировка узла (Argon2id)…[/dim]")
        else:
            print("Разблокировка узла…")

        self._start_node_thread(password)
        self._banner()

        history_file = os.path.join(self.args.data_dir, ".cli_history")
        completer = WordCompleter(COMMANDS, ignore_case=True) if HAS_PTOOLKIT else None

        if HAS_PTOOLKIT:
            session = PromptSession(
                history=FileHistory(history_file),
                auto_suggest=AutoSuggestFromHistory(),
                completer=completer,
            )

        def _get_input(prompt: str) -> str:
            if HAS_PTOOLKIT:
                with patch_stdout():
                    return session.prompt(prompt)
            return input(prompt)

        while True:
            try:
                addr_short = (self.node.address[:8] + "…") if self.node else "offline"
                line = _get_input(f"murnet({addr_short})> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            parts = line.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("quit", "exit"):
                break
            elif cmd == "help":
                print(HELP_TEXT)
            elif cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
            elif cmd == "status":
                self.cmd_status(args)
            elif cmd == "peers":
                self.cmd_peers(args)
            elif cmd == "connect":
                self.cmd_connect(args)
            elif cmd == "send":
                self.cmd_send(args)
            elif cmd == "inbox":
                self.cmd_inbox(args)
            elif cmd == "register":
                self.cmd_register(args)
            elif cmd == "lookup":
                self.cmd_lookup(args)
            elif cmd == "dht":
                self.cmd_dht(args)
            elif cmd == "routes":
                self.cmd_routes(args)
            elif cmd == "migrate":
                self.cmd_migrate(args)
            elif cmd == "publish":
                self.cmd_publish(args)
            elif cmd == "subscribe":
                self.cmd_subscribe(args)
            elif cmd == "objects":
                self.cmd_objects(args)
            elif cmd == "vpn":
                self.cmd_vpn(args)
            elif cmd == "stop":
                self._stop_node()
                console.print("Node stopped.")
            elif cmd == "start":
                if not self.node:
                    from core.identity.keystore import prompt_password_cli
                    pw = prompt_password_cli(self.args.data_dir)
                    self._start_node_thread(pw)
                    console.print("Node started.")
                else:
                    console.print("Already running.")
            else:
                console.print(f"Unknown command: '{cmd}'. Type 'help'.")

        console.print("\nShutting down…" if not HAS_RICH else "\n[dim]Shutting down…[/dim]")
        self._stop_node()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="murnet",
        description="Murnet v6.2 — Async P2P node CLI",
    )
    p.add_argument("--port",     type=int, default=8888,      help="P2P UDP port (default: 8888)")
    p.add_argument("--api-port", type=int, default=8080,      help="REST API port (default: 8080)")
    p.add_argument("--data-dir", type=str, default="./data",  help="Data directory (default: ./data)")
    p.add_argument("--no-api",   action="store_true",         help="Disable REST API server")
    p.add_argument("--log-level",type=str, default="WARNING",
                   choices=["DEBUG","INFO","WARNING","ERROR"], help="Log level")
    return p


def main():
    import logging
    args = build_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    MurnetCLI(args).run()


if __name__ == "__main__":
    main()
