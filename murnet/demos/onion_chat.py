"""
MurNet Onion Chat — prototype messenger over onion routing.

Запуск:  python demos/onion_chat.py

Что происходит:
  - Поднимаются 5 нод в одном процессе (Alice, Bob, Guard, Middle, Exit)
  - Alice и Bob строят 3-хоп circuit через Guard → Middle → Exit
  - Сообщения идут через реальный OnionRouter (X25519 + AES-256-GCM)
  - UI разделён: чат Alice | анимация маршрута | чат Bob
  - Tab переключает кто пишет
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, RichLog, Static
from textual.reactive import reactive

from murnet.core.onion.cell import OnionCell, OnionCmd, is_onion_cell
from murnet.core.onion.circuit import CircuitOrigin
from murnet.core.onion.router import OnionRouter

# ─────────────────────────────────────────────────────────────────────────────
# In-process network (no UDP — pure asyncio)
# ─────────────────────────────────────────────────────────────────────────────

class Network:
    def __init__(self):
        self._routers: dict[str, OnionRouter] = {}
        self.packet_log: list[tuple[str, str, str]] = []  # (from, to, cmd)

    def register(self, router: OnionRouter) -> None:
        self._routers[router.addr] = router

    def make_send(self, from_addr: str) -> Callable:
        async def _send(to_addr: str, cell: OnionCell) -> None:
            self.packet_log.append((from_addr, to_addr, cell.cmd.value))
            target = self._routers.get(to_addr)
            if target:
                await target.handle_cell(cell, from_addr)
        return _send

    def wire(self, *routers: OnionRouter) -> None:
        for r in routers:
            self.register(r)
            r.send_fn = self.make_send(r.addr)


# ─────────────────────────────────────────────────────────────────────────────
# Chat node: messenger protocol on top of OnionRouter
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChatMessage:
    sender:    str
    text:      str
    ts:        float = field(default_factory=time.time)
    stream_id: str = "chat"


class ChatNode:
    def __init__(self, name: str, net: Network):
        self.name    = name
        self.router  = OnionRouter(name)
        self.circuit: Optional[CircuitOrigin] = None
        self.on_message: Optional[Callable[[ChatMessage], None]] = None
        net.register(self.router)
        self.router.send_fn = net.make_send(name)
        self.router.on_data  = self._on_data

    def _on_data(self, stream_id: str, data: bytes) -> None:
        try:
            msg = json.loads(data)
            if msg.get("type") == "chat" and msg.get("from") != self.name:
                cm = ChatMessage(
                    sender=msg["from"],
                    text=msg["text"],
                    ts=msg.get("ts", time.time()),
                )
                if self.on_message:
                    self.on_message(cm)
        except Exception:
            pass

    async def build_circuit(self, relays: list[str]) -> None:
        self.circuit = await self.router.build_circuit(relays)

    async def send(self, text: str) -> None:
        if not self.circuit:
            return
        payload = json.dumps({
            "type": "chat",
            "from": self.name,
            "text": text,
            "ts":   time.time(),
        }).encode()
        await self.router.send_data(self.circuit, "chat", payload)


# ─────────────────────────────────────────────────────────────────────────────
# Route panel widget
# ─────────────────────────────────────────────────────────────────────────────

RELAY_NAMES = ["Guard", "Middle", "Exit"]

class RoutePanel(Static):
    """Animated visualization of a packet traversing the onion circuit."""

    DEFAULT_CSS = """
    RoutePanel {
        height: 100%;
        padding: 1 2;
        color: $text-muted;
    }
    """

    def render(self) -> str:
        lines = [
            "[bold cyan]Onion Circuits[/bold cyan]",
            "",
            "[bold green]Alice[/bold green] [dim]→ Guard→Middle→Bob[/dim]",
            "  │",
            "  ▼  [dim]enc K1(K2(K3(…)))[/dim]",
            "[yellow]Guard[/yellow]",
            "  │",
            "  ▼  [dim]enc K2(K3(…))[/dim]",
            "[yellow]Middle[/yellow]",
            "  │",
            "  ▼  [dim]enc K3(…)[/dim]",
            "[bold blue]Bob[/bold blue] [dim](exit)[/dim]",
            "",
            "[bold blue]Bob[/bold blue] [dim]→ Exit→Middle→Alice[/dim]",
            "  │",
            "  ▼  [dim]enc K1(K2(K3(…)))[/dim]",
            "[yellow]Exit[/yellow]",
            "  │",
            "  ▼  [dim]enc K2(K3(…))[/dim]",
            "[yellow]Middle[/yellow]",
            "  │",
            "  ▼  [dim]enc K3(…)[/dim]",
            "[bold green]Alice[/bold green] [dim](exit)[/dim]",
            "",
            "[dim]Keys: X25519 ECDH[/dim]",
            "[dim]Enc:  AES-256-GCM[/dim]",
        ]
        return "\n".join(lines)


class AnimatedRoute(RichLog):
    """Shows live packet events."""
    DEFAULT_CSS = """
    AnimatedRoute {
        height: 100%;
        border: solid $accent;
        padding: 0 1;
    }
    """


# ─────────────────────────────────────────────────────────────────────────────
# Main app
# ─────────────────────────────────────────────────────────────────────────────

ALICE_STYLE = "bold green"
BOB_STYLE   = "bold blue"
SYS_STYLE   = "dim italic"

CSS = """
Screen {
    background: #0d1117;
}

#header-bar {
    height: 3;
    background: #161b22;
    color: #58a6ff;
    content-align: center middle;
    text-style: bold;
}

#cols {
    height: 1fr;
}

#alice-pane {
    width: 1fr;
    border: solid #30a46c;
    border-title-color: #30a46c;
}

#route-pane {
    width: 30;
    border: solid #58a6ff;
    border-title-color: #58a6ff;
    padding: 1 1;
    color: #8b949e;
}

#bob-pane {
    width: 1fr;
    border: solid #58a6ff;
    border-title-color: #58a6ff;
}

#alice-log, #bob-log {
    height: 1fr;
    padding: 0 1;
}

#input-bar {
    height: 3;
    background: #161b22;
}

#chat-input {
    width: 1fr;
    border: solid #30363d;
    background: #0d1117;
}

#sender-label {
    width: 14;
    content-align: center middle;
    color: #30a46c;
    text-style: bold;
    padding: 0 1;
}
"""


class OnionChatApp(App):
    CSS = CSS
    BINDINGS = [
        Binding("tab",    "toggle_sender", "Switch Alice↔Bob"),
        Binding("ctrl+c", "quit",          "Quit"),
    ]

    active_sender: reactive[str] = reactive("Alice")

    def __init__(self):
        super().__init__()
        self.net   = Network()
        self.alice = ChatNode("Alice", self.net)
        self.bob   = ChatNode("Bob",   self.net)
        # Relay nodes — no UI, just exist to relay
        self.guard  = OnionRouter("Guard")
        self.middle = OnionRouter("Middle")
        self.exit   = OnionRouter("Exit")
        self.net.wire(self.guard, self.middle, self.exit)
        # Callbacks
        self.alice.on_message = lambda m: self._on_incoming("alice-log", m, BOB_STYLE)
        self.bob.on_message   = lambda m: self._on_incoming("bob-log",   m, ALICE_STYLE)

    def compose(self) -> ComposeResult:
        yield Static(
            "  🌌  MurNet Onion Chat  •  3-hop circuit  •  AES-256-GCM  •  X25519",
            id="header-bar",
        )
        with Horizontal(id="cols"):
            with Vertical(id="alice-pane"):
                yield RichLog(id="alice-log", markup=True, highlight=False)
            with Vertical(id="route-pane"):
                yield RoutePanel()
            with Vertical(id="bob-pane"):
                yield RichLog(id="bob-log", markup=True, highlight=False)
        with Horizontal(id="input-bar"):
            yield Static("  Alice  ▶", id="sender-label")
            yield Input(placeholder="Type a message…", id="chat-input")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#alice-pane").border_title = "Alice  🔐"
        self.query_one("#bob-pane").border_title   = "Bob  🔐"
        self.query_one("#route-pane").border_title = "Route"
        self.run_worker(self._setup(), exclusive=False)

    async def _setup(self) -> None:
        alice_log = self.query_one("#alice-log", RichLog)
        bob_log   = self.query_one("#bob-log",   RichLog)

        alice_log.write("[dim]Building onion circuit…[/dim]")
        bob_log.write("[dim]Building onion circuit…[/dim]")

        # Alice:  Guard → Middle → Bob   (data lands at Bob's router as exit)
        # Bob:    Exit  → Middle → Alice (data lands at Alice's router as exit)
        await self.alice.build_circuit(["Guard", "Middle", "Bob"])
        await self.bob.build_circuit(["Exit", "Middle", "Alice"])

        alice_log.write("[dim]Circuit ready ✓  (Guard → Middle → Bob)[/dim]")
        alice_log.write("")
        bob_log.write("[dim]Circuit ready ✓  (Exit → Middle → Alice)[/dim]")
        bob_log.write("")

        # Auto demo message
        await asyncio.sleep(0.4)
        await self.alice.send("Привет, Боб! Меня слышно?")
        await asyncio.sleep(0.3)
        await self.bob.send("Слышу! Сигнал чистый. Три хопа 🔒")

    def _on_incoming(self, log_id: str, msg: ChatMessage, style: str) -> None:
        log = self.query_one(f"#{log_id}", RichLog)
        ts  = time.strftime("%H:%M:%S", time.localtime(msg.ts))
        log.write(f"[{style}]{msg.sender}[/{style}]  [dim]{ts}[/dim]")
        log.write(f"  {msg.text}")
        log.write("")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.clear()

        sender = self.active_sender
        node   = self.alice if sender == "Alice" else self.bob
        log_id = "alice-log" if sender == "Alice" else "bob-log"
        style  = ALICE_STYLE if sender == "Alice" else BOB_STYLE

        # Show in sender's panel immediately
        log = self.query_one(f"#{log_id}", RichLog)
        ts  = time.strftime("%H:%M:%S")
        log.write(f"[{style}]{sender}[/{style}]  [dim]{ts}[/dim]")
        log.write(f"  {text}")
        log.write("")

        await node.send(text)

    def action_toggle_sender(self) -> None:
        self.active_sender = "Bob" if self.active_sender == "Alice" else "Alice"
        label = self.query_one("#sender-label", Static)
        if self.active_sender == "Alice":
            label.update("  Alice  ▶")
            label.styles.color = "#30a46c"
        else:
            label.update("  Bob    ▶")
            label.styles.color = "#58a6ff"

    def watch_active_sender(self, sender: str) -> None:
        inp = self.query_one("#chat-input", Input)
        inp.placeholder = f"Type as {sender}…"


if __name__ == "__main__":
    OnionChatApp().run()
