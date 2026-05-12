"""
MurNet VPN Tunnel — TCP-over-MurNet circuit manager.

Each SOCKS5 connection becomes a Circuit routed through the MurNet P2P
network to an exit node.  TCP data is chunked into VPN messages:

  Client → Exit:
    {"type":"CONNECT","circuit":"<uuid>","dst_host":"...","dst_port":443}

  Exit → Client:
    {"type":"CONNECTED","circuit":"<uuid>"}
    {"type":"ERROR","circuit":"<uuid>","msg":"<reason>"}

  Both directions (data relay):
    {"type":"DATA","circuit":"<uuid>","data":"<base64>"}

  Both directions (teardown):
    {"type":"CLOSE","circuit":"<uuid>"}
"""
from __future__ import annotations

import asyncio
import base64
import logging
import socket
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable, Dict, Optional, Tuple

if TYPE_CHECKING:
    from murnet.core.node.node import SecureMurnetNode

logger = logging.getLogger("murnet.vpn.tunnel")

_CHUNK = 8192          # bytes per DATA message
_CONNECT_TIMEOUT = 15  # seconds to wait for exit node CONNECTED reply
_MAX_RECV_QUEUE = 256  # circuit receive buffer (chunks)


class CircuitState(str, Enum):
    CONNECTING = "CONNECTING"
    CONNECTED  = "CONNECTED"
    CLOSING    = "CLOSING"
    CLOSED     = "CLOSED"


@dataclass
class Circuit:
    id: str
    dst_host: str
    dst_port: int
    exit_peer: str              # MurNet address of the exit node
    state: CircuitState = CircuitState.CONNECTING
    recv_queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(_MAX_RECV_QUEUE))
    connected_event: asyncio.Event = field(default_factory=asyncio.Event)
    closed_event: asyncio.Event = field(default_factory=asyncio.Event)
    error: Optional[str] = None


class TunnelManager:
    """
    Manages VPN circuits over a MurNet node.

    Usage (client side):
        mgr = TunnelManager(node, exit_peer_address)
        await mgr.start(loop)
        circuit = await mgr.connect("google.com", 443)
        await circuit.recv_queue.get()  # bytes from remote

    Usage (exit / server side):
        mgr = TunnelManager(node, exit_peer_address=None, exit_mode=True)
        await mgr.start(loop)
        # node.extra_handlers['vpn'] is set automatically
    """

    def __init__(
        self,
        node: "SecureMurnetNode",
        exit_peer: Optional[str] = None,
        exit_mode: bool = False,
    ):
        self.node = node
        self.exit_peer = exit_peer      # target exit node MurNet address (client mode)
        self.exit_mode = exit_mode      # True → this node acts as exit
        self._circuits: Dict[str, Circuit] = {}
        self._exit_sockets: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        # Async node (AsyncMurnetNode): handler can be a coroutine
        # Sync node (SecureMurnetNode): use thread-safe bridge
        if asyncio.iscoroutinefunction(getattr(self.node, "send_vpn", None)):
            self.node.extra_handlers["vpn"] = self._on_vpn_message_async
        else:
            self.node.extra_handlers["vpn"] = self._on_vpn_message_threadsafe
        mode = "exit+client" if (self.exit_mode and self.exit_peer) else ("exit" if self.exit_mode else "client")
        logger.info("TunnelManager started in %s mode (my_id=%s)", mode, self.node.address[:12])

    def stop(self) -> None:
        self.node.extra_handlers.pop("vpn", None)
        for c in list(self._circuits.values()):
            c.state = CircuitState.CLOSED
            c.closed_event.set()

    # ------------------------------------------------------------------
    # Client API
    # ------------------------------------------------------------------

    async def connect(self, dst_host: str, dst_port: int) -> Circuit:
        """
        Open a new circuit to (dst_host, dst_port) through the exit peer.
        Waits until the exit node replies CONNECTED (or times out).
        """
        if not self.exit_peer:
            raise RuntimeError("No exit peer configured")

        circuit = Circuit(
            id=str(uuid.uuid4()),
            dst_host=dst_host,
            dst_port=dst_port,
            exit_peer=self.exit_peer,
        )
        self._circuits[circuit.id] = circuit

        self._send_vpn(self.exit_peer, {
            "type": "CONNECT",
            "circuit": circuit.id,
            "dst_host": dst_host,
            "dst_port": dst_port,
        })

        try:
            await asyncio.wait_for(circuit.connected_event.wait(), timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            circuit.state = CircuitState.CLOSED
            circuit.error = "Connection timed out"
            del self._circuits[circuit.id]
            raise ConnectionError(f"Exit peer did not respond for {dst_host}:{dst_port}")

        if circuit.state != CircuitState.CONNECTED:
            del self._circuits[circuit.id]
            raise ConnectionError(circuit.error or "Circuit failed")

        return circuit

    async def send_data(self, circuit: Circuit, data: bytes) -> None:
        """Send raw bytes through an established circuit."""
        if circuit.state != CircuitState.CONNECTED:
            return
        for i in range(0, len(data), _CHUNK):
            chunk = data[i:i + _CHUNK]
            self._send_vpn(circuit.exit_peer, {
                "type": "DATA",
                "circuit": circuit.id,
                "data": base64.b64encode(chunk).decode(),
            })

    def close_circuit(self, circuit: Circuit) -> None:
        """Tear down a circuit."""
        if circuit.state in (CircuitState.CLOSING, CircuitState.CLOSED):
            return
        circuit.state = CircuitState.CLOSING
        self._send_vpn(circuit.exit_peer, {
            "type": "CLOSE",
            "circuit": circuit.id,
        })
        circuit.state = CircuitState.CLOSED
        circuit.closed_event.set()
        self._circuits.pop(circuit.id, None)

    # ------------------------------------------------------------------
    # Node-type-agnostic send helper
    # ------------------------------------------------------------------

    def _send_vpn(self, to_addr: str, payload: dict) -> None:
        """Send a VPN message regardless of whether the node is sync or async."""
        result = self.node.send_vpn(to_addr, payload)
        if asyncio.iscoroutine(result):
            if self._loop is not None and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(result, self._loop)
            else:
                result.close()  # discard to avoid 'coroutine was never awaited'

    # ------------------------------------------------------------------
    # Message dispatcher (called from MurNet thread → bridged to asyncio)
    # ------------------------------------------------------------------

    def _on_vpn_message_threadsafe(
        self,
        payload: dict,
        from_addr: str,
        ip: str,
        port: int,
    ) -> None:
        if self._loop is None:
            return
        asyncio.run_coroutine_threadsafe(
            self._dispatch(payload, from_addr),
            self._loop,
        )

    async def _on_vpn_message_async(
        self,
        payload: dict,
        from_addr: str,
        ip: str,
        port: int,
    ) -> None:
        """Handler for AsyncMurnetNode — already in event loop."""
        await self._dispatch(payload, from_addr)

    async def _dispatch(self, payload: dict, from_addr: str) -> None:
        msg_type   = payload.get("type", "")
        circuit_id = payload.get("circuit", "")

        # ---- Responses received by the CLIENT side ----
        if msg_type == "CONNECTED":
            c = self._circuits.get(circuit_id)
            if c:
                c.state = CircuitState.CONNECTED
                c.connected_event.set()

        elif msg_type == "ERROR":
            c = self._circuits.get(circuit_id)
            if c:
                c.state = CircuitState.CLOSED
                c.error = payload.get("msg", "Remote error")
                c.connected_event.set()  # unblock connect() waiter

        elif msg_type == "DATA":
            c = self._circuits.get(circuit_id)
            if c and c.state == CircuitState.CONNECTED:
                raw = base64.b64decode(payload.get("data", ""))
                if raw:
                    try:
                        c.recv_queue.put_nowait(raw)
                    except asyncio.QueueFull:
                        logger.warning("Circuit %s recv_queue full, dropping chunk", circuit_id[:8])

        elif msg_type == "CLOSE":
            c = self._circuits.pop(circuit_id, None)
            if c:
                c.state = CircuitState.CLOSED
                c.closed_event.set()
                try:
                    c.recv_queue.put_nowait(b"")  # EOF sentinel
                except asyncio.QueueFull:
                    pass

        # ---- Requests received by the EXIT NODE ----
        elif msg_type == "CONNECT" and self.exit_mode:
            asyncio.ensure_future(
                self._exit_handle_connect(
                    circuit_id=circuit_id,
                    dst_host=payload.get("dst_host", ""),
                    dst_port=int(payload.get("dst_port", 0)),
                    client_addr=from_addr,
                )
            )

        elif msg_type == "DATA" and self.exit_mode:
            pair = self._exit_sockets.get(circuit_id)
            if pair:
                _, writer = pair
                raw = base64.b64decode(payload.get("data", ""))
                if raw:
                    writer.write(raw)
                    await writer.drain()

        elif msg_type == "CLOSE" and self.exit_mode:
            pair = self._exit_sockets.pop(circuit_id, None)
            if pair:
                _, writer = pair
                writer.close()

    # ------------------------------------------------------------------
    # Exit node: handle CONNECT, relay data
    # ------------------------------------------------------------------

    async def _exit_handle_connect(
        self,
        circuit_id: str,
        dst_host: str,
        dst_port: int,
        client_addr: str,
    ) -> None:
        logger.info("[exit] CONNECT %s:%s (circuit=%s)", dst_host, dst_port, circuit_id[:8])
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(dst_host, dst_port),
                timeout=10,
            )
        except Exception as exc:
            logger.warning("[exit] connect to %s:%s failed: %s", dst_host, dst_port, exc)
            self._send_vpn(client_addr, {
                "type": "ERROR",
                "circuit": circuit_id,
                "msg": str(exc),
            })
            return

        self._exit_sockets[circuit_id] = (reader, writer)
        self.node.send_vpn(client_addr, {
            "type": "CONNECTED",
            "circuit": circuit_id,
        })
        logger.info("[exit] CONNECTED %s:%s", dst_host, dst_port)

        # Relay remote → client
        try:
            while True:
                chunk = await reader.read(_CHUNK)
                if not chunk:
                    break
                self._send_vpn(client_addr, {
                    "type": "DATA",
                    "circuit": circuit_id,
                    "data": base64.b64encode(chunk).decode(),
                })
        except Exception:
            pass
        finally:
            self._exit_sockets.pop(circuit_id, None)
            writer.close()
            self._send_vpn(client_addr, {
                "type": "CLOSE",
                "circuit": circuit_id,
            })
            logger.info("[exit] closed %s (circuit=%s)", dst_host, circuit_id[:8])
