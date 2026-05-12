"""
MurNet onion node — relay or chat participant over real TCP.

────────────────────────────────────────────────────────────────
QUICK START (5 terminals, all on localhost)
────────────────────────────────────────────────────────────────

  # 1. Three relay nodes (no UI — just forward cells):
  python demos/onion_node.py --bind 127.0.0.1:9001 --name Guard
  python demos/onion_node.py --bind 127.0.0.1:9002 --name Middle
  python demos/onion_node.py --bind 127.0.0.1:9003 --name Exit

  # 2. Bob — listens, builds circuit back to Alice:
  python demos/onion_node.py --bind 127.0.0.1:9004 --name Bob  \\
      --peer Exit=127.0.0.1:9003                                \\
      --peer Middle=127.0.0.1:9002                              \\
      --peer Alice=127.0.0.1:9000                               \\
      --circuit Exit,Middle,Alice

  # 3. Alice — connects through relays, exits at Bob:
  python demos/onion_node.py --bind 127.0.0.1:9000 --name Alice \\
      --peer Guard=127.0.0.1:9001                               \\
      --peer Middle=127.0.0.1:9002                              \\
      --peer Bob=127.0.0.1:9004                                 \\
      --circuit Guard,Middle,Bob

────────────────────────────────────────────────────────────────
HOW IT WORKS
────────────────────────────────────────────────────────────────

  Alice circuit:  Alice → Guard → Middle → Bob (exit)
  Bob circuit:    Bob   → Exit  → Middle → Alice (exit)

  Each node's router.addr = "host:port" (its listening address).
  The "src" field in every TCP envelope carries the sender's
  listening addr, so relays can route replies without a directory.

  Chat nodes act simultaneously as:
    - originator  of their own circuit
    - exit relay  for the other party's circuit
────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Footer, Input, RichLog, Static
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False
    # Stubs so the class body parses without textual installed.
    # ChatApp is never instantiated in relay mode.
    App = object
    Binding = lambda *a, **kw: None  # type: ignore[assignment]
    ComposeResult = None
    class _W:
        pass
    Horizontal = Vertical = Footer = Input = RichLog = Static = _W

from murnet.core.onion.router import OnionRouter
from murnet.core.onion.transport import OnionTransport

_AUTO_HOPS = 3   # how many relays to pick when --circuit auto

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(name)s %(levelname)s  %(message)s",
)


# ─────────────────────────────────────────────────────────────────────────────
# Chat TUI  (used when --circuit is given)
# ─────────────────────────────────────────────────────────────────────────────

CSS = """
Screen { background: #0d1117; }

#title {
    height: 3;
    background: #161b22;
    color: #58a6ff;
    content-align: center middle;
    text-style: bold;
}

#chat-log {
    height: 1fr;
    padding: 0 1;
    border: solid #30363d;
}

#status-bar {
    height: 1;
    background: #161b22;
    color: #8b949e;
    padding: 0 2;
}

#input-bar {
    height: 3;
    background: #161b22;
}

#chat-input {
    width: 1fr;
    border: solid #30363d;
    background: #0d1117;
    color: #e6edf3;
}
"""


class ChatApp(App):
    CSS = CSS
    BINDINGS = [Binding("ctrl+c", "quit", "Quit")]

    def __init__(
        self,
        display_name: str,
        transport: OnionTransport,
        circuit_hops: list[str],
    ) -> None:
        super().__init__()
        self._name      = display_name
        self._transport = transport
        self._hops      = circuit_hops        # friendly names, resolved later
        self._router    = transport.router
        self._circuit   = None

    # ── layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        bind_addr = f"{self._transport.bind_host}:{self._transport.bind_port}"
        yield Static(
            f"  MurNet  •  {self._name} @ {bind_addr}  •  AES-256-GCM  •  X25519",
            id="title",
        )
        with Vertical():
            yield RichLog(id="chat-log", markup=True, highlight=False)
        yield Static("", id="status-bar")
        with Horizontal(id="input-bar"):
            yield Input(placeholder="Type a message and press Enter…", id="chat-input")
        yield Footer()

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        self._router.on_data = self._on_data
        self.run_worker(self._setup(), exclusive=False)

    async def _setup(self) -> None:
        log = self.query_one("#chat-log", RichLog)

        await self._transport.start()
        self._set_status("listening…")
        log.write(f"[dim]Bound to {self._transport.bind_host}:{self._transport.bind_port}[/dim]")

        if not self._hops:
            log.write("[dim]No --circuit given — relay-only mode.[/dim]")
            self._set_status("relay mode")
            return

        # --circuit auto: wait for gossip to populate directory, then pick
        if self._hops == ["auto"]:
            log.write("[dim]Waiting for relay gossip…[/dim]")
            self._set_status("discovering relays…")
            for _ in range(20):   # up to 10 s
                if len(self._transport.directory) >= _AUTO_HOPS:
                    break
                await asyncio.sleep(0.5)
            try:
                own = self._router.addr
                auto_addrs = self._transport.directory.pick(_AUTO_HOPS, exclude=[own])
                resolved   = auto_addrs
                path_str   = " -> ".join(auto_addrs)
                log.write(f"[dim]Auto-selected: {path_str}[/dim]")
            except RuntimeError as exc:
                log.write(f"[bold red]Auto-circuit failed:[/bold red] {exc}")
                self._set_status("not enough relays discovered")
                return
        else:
            resolved = [self._transport.resolve(h) for h in self._hops]
            path_str = " -> ".join(self._hops)

        log.write(f"[dim]Building circuit: {path_str}…[/dim]")
        self._set_status(f"building circuit through {path_str}")

        try:
            self._circuit = await self._router.build_circuit(resolved)
            log.write(f"[dim]Circuit ready  ({path_str})[/dim]")
            log.write("")
            self._set_status(f"circuit: {path_str}  |  type to send")
        except Exception as exc:
            log.write(f"[bold red]Circuit failed:[/bold red] {exc}")
            self._set_status("circuit FAILED — check relays are running")

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#status-bar", Static).update(f" {text}")
        except Exception:
            pass

    # ── incoming data ─────────────────────────────────────────────────────────

    def _on_data(self, stream_id: str, data: bytes) -> None:
        try:
            msg = json.loads(data)
            if msg.get("type") == "chat" and msg.get("from") != self._name:
                sender = msg["from"]
                text   = msg["text"]
                ts     = time.strftime("%H:%M:%S", time.localtime(msg.get("ts", time.time())))
                log    = self.query_one("#chat-log", RichLog)
                log.write(f"[bold cyan]{sender}[/bold cyan]  [dim]{ts}[/dim]")
                log.write(f"  {text}")
                log.write("")
        except Exception:
            pass

    # ── send ──────────────────────────────────────────────────────────────────

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.clear()
        if not text:
            return
        if not self._circuit:
            log = self.query_one("#chat-log", RichLog)
            log.write("[dim italic]No circuit yet — wait for setup to complete.[/dim italic]")
            return

        payload = json.dumps({
            "type": "chat",
            "from": self._name,
            "text": text,
            "ts":   time.time(),
        }).encode()

        try:
            await self._router.send_data(self._circuit, "chat", payload)
        except Exception as exc:
            log = self.query_one("#chat-log", RichLog)
            log.write(f"[bold red]Send failed:[/bold red] {exc}")
            return

        ts  = time.strftime("%H:%M:%S")
        log = self.query_one("#chat-log", RichLog)
        log.write(f"[bold green]{self._name}[/bold green]  [dim]{ts}[/dim]")
        log.write(f"  {text}")
        log.write("")


# ─────────────────────────────────────────────────────────────────────────────
# Relay mode  (no TUI — used when --circuit is NOT given)
# ─────────────────────────────────────────────────────────────────────────────

async def run_relay(
    name: str,
    bind_host: str,
    bind_port: int,
    peers: dict[str, str],
    api_port: int = 0,
    announce: bool = False,
) -> None:
    addr      = f"{bind_host}:{bind_port}"
    router    = OnionRouter(addr)
    transport = OnionTransport(router, bind_host, bind_port, peers,
                               self_name=name if announce else None)
    await transport.start()

    print(f"[{name}]  relay  {addr}  --  waiting for circuits"
          + ("  [announcing]" if announce else ""))

    if api_port:
        try:
            from murnet.api.onion_api import serve as api_serve
            asyncio.create_task(api_serve(router, transport, "0.0.0.0", api_port))
            print(f"[{name}]  status API  http://0.0.0.0:{api_port}/api/status")
        except Exception as exc:
            print(f"[{name}]  API disabled: {exc}")

    print("  Ctrl+C to stop\n")

    cells_relayed = 0

    def _count(_sid: str, _data: bytes) -> None:
        nonlocal cells_relayed
        cells_relayed += 1

    router.on_data = _count

    try:
        while True:
            await asyncio.sleep(5)
            relays    = len(router._relays)
            known_dir = len(transport.directory)
            print(f"  [{name}]  relay entries: {relays}"
                  f"  |  data cells: {cells_relayed}"
                  f"  |  dir: {known_dir} relays")
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await transport.stop()
        print(f"\n[{name}]  stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MurNet onion node",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example (5 terminals):\n"
            "  python demos/onion_node.py --bind 127.0.0.1:9001 --name Guard\n"
            "  python demos/onion_node.py --bind 127.0.0.1:9002 --name Middle\n"
            "  python demos/onion_node.py --bind 127.0.0.1:9003 --name Exit\n"
            "  python demos/onion_node.py --bind 127.0.0.1:9004 --name Bob "
            "--peer Exit=127.0.0.1:9003 --peer Middle=127.0.0.1:9002 "
            "--peer Alice=127.0.0.1:9000 --circuit Exit,Middle,Alice\n"
            "  python demos/onion_node.py --bind 127.0.0.1:9000 --name Alice "
            "--peer Guard=127.0.0.1:9001 --peer Middle=127.0.0.1:9002 "
            "--peer Bob=127.0.0.1:9004 --circuit Guard,Middle,Bob\n"
        ),
    )
    p.add_argument(
        "--bind", required=True,
        metavar="HOST:PORT",
        help="Address to listen on  (e.g. 127.0.0.1:9001)",
    )
    p.add_argument(
        "--name", default=None,
        help="Display name (default: bind address)",
    )
    p.add_argument(
        "--peer", action="append", default=[],
        metavar="NAME=HOST:PORT",
        help="Register a named peer  (repeatable)",
    )
    p.add_argument(
        "--circuit", default=None,
        metavar="HOP1,HOP2,...",
        help="Comma-separated relay names — activates chat mode",
    )
    p.add_argument(
        "--log", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: WARNING)",
    )
    p.add_argument(
        "--api-port", type=int, default=0,
        metavar="PORT",
        help="Enable HTTP status API on this port (relay mode only)",
    )
    p.add_argument(
        "--announce", action="store_true",
        help="Advertise this node as a relay via gossip (relay mode only)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log)

    host, port_s = args.bind.rsplit(":", 1)
    port = int(port_s)
    name = args.name or args.bind

    peers: dict[str, str] = {}
    for spec in args.peer:
        k, v = spec.split("=", 1)
        peers[k.strip()] = v.strip()

    circuit_hops: list[str] = (
        [h.strip() for h in args.circuit.split(",")]
        if args.circuit else []
    )

    if circuit_hops:
        if not HAS_TEXTUAL:
            print("textual not installed -- chat mode unavailable.")
            print("Install with:  pip install textual")
            sys.exit(1)
        router    = OnionRouter(f"{host}:{port}")
        transport = OnionTransport(router, host, port, peers)
        ChatApp(name, transport, circuit_hops).run()
    else:
        # Relay mode — plain asyncio
        asyncio.run(run_relay(name, host, port, peers,
                              api_port=args.api_port,
                              announce=args.announce))


if __name__ == "__main__":
    main()
