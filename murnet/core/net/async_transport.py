"""
MURNET ASYNC TRANSPORT v6.0
asyncio DatagramProtocol — drops threading.Thread in favour of asyncio tasks.

Drop-in companion to core/transport.py.  The existing Transport class is kept
for backwards-compat; this module adds AsyncTransport that uses the same
PacketHeader / PeerConnection / RateLimiter data structures.
"""

import asyncio
import json
import logging
import random
import struct
import time
import hmac
from typing import Callable, Dict, List, Optional, Tuple, Awaitable

from murnet.core.net.transport import (
    PacketHeader,
    PacketType,
    PeerConnection,
    RateLimiter,
)
from murnet.core.identity.crypto import blake2b_hash, secure_random_bytes, constant_time_compare

logger = logging.getLogger(__name__)

_KEEPALIVE_INTERVAL = 30.0   # seconds
_PEER_TIMEOUT       = 120.0  # seconds without traffic → disconnect
_MAX_PACKET_SIZE    = 1400
_HMAC_KEY_SIZE      = 32


# ---------------------------------------------------------------------------
# asyncio DatagramProtocol
# ---------------------------------------------------------------------------

class _MurnetDatagramProtocol(asyncio.DatagramProtocol):
    """Low-level asyncio UDP handler — delegates to AsyncTransport."""

    def __init__(self, transport_obj: "AsyncTransport"):
        self._t = transport_obj
        self._sock: Optional[asyncio.DatagramTransport] = None

    # -- asyncio callbacks --------------------------------------------------

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._sock = transport
        self._t._sock = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        asyncio.ensure_future(self._t._handle_datagram(data, addr))

    def error_received(self, exc: Exception):
        logger.warning("UDP socket error: %s", exc)

    def connection_lost(self, exc: Optional[Exception]):
        logger.info("UDP socket closed: %s", exc)


# ---------------------------------------------------------------------------
# AsyncTransport
# ---------------------------------------------------------------------------

class AsyncTransport:
    """
    Async UDP transport for Murnet v6.0.

    Usage:
        transport = AsyncTransport(port=8888, hmac_key=key)
        await transport.start()
        await transport.send_packet(PacketType.PING, b"", ("10.0.0.1", 8888))
        await transport.stop()
    """

    def __init__(
        self,
        port: int = 8888,
        hmac_key: Optional[bytes] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.port = port
        self.hmac_key: bytes = hmac_key or secure_random_bytes(_HMAC_KEY_SIZE)
        self._loop = loop  # set explicitly only in tests

        self.peers: Dict[Tuple[str, int], PeerConnection] = {}
        self.rate_limiter = RateLimiter(rate=100, burst=200)
        self._seq: int = random.randint(1, 2**31)

        self._sock: Optional[asyncio.DatagramTransport] = None
        self._running = False

        # Callbacks (assign before start())
        self.on_message: Optional[Callable[[bytes, str, Tuple[str, int]], Awaitable[None]]] = None
        self.on_peer_connected: Optional[Callable[[str, Tuple[str, int]], Awaitable[None]]] = None
        self.on_peer_disconnected: Optional[Callable[[str, Tuple[str, int]], Awaitable[None]]] = None

        # Sync handlers registered via register_handler() (compatible with Transport API)
        self._message_handlers: List[Callable] = []
        self._connect_handlers: List[Callable] = []

        # Background task handles
        self._keepalive_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self):
        """Bind the UDP socket and start background tasks."""
        loop = self._loop or asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _MurnetDatagramProtocol(self),
            local_addr=("0.0.0.0", self.port),
        )
        self._running = True
        logger.info("AsyncTransport listening on UDP :%d", self.port)

        self._keepalive_task = asyncio.ensure_future(self._keepalive_loop())
        self._cleanup_task   = asyncio.ensure_future(self._cleanup_loop())

    async def stop(self):
        """Gracefully stop transport."""
        self._running = False
        for task in (self._keepalive_task, self._cleanup_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if self._sock:
            self._sock.close()
        logger.info("AsyncTransport stopped.")

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def send_packet(
        self,
        ptype: PacketType,
        payload: bytes,
        addr: Tuple[str, int],
        *,
        ack_seq: int = 0,
    ) -> bool:
        """Encode, authenticate and send one UDP datagram."""
        if not self._sock:
            return False

        seq = self._next_seq()
        header = PacketHeader(
            version=1,
            packet_type=ptype,
            sequence=seq,
            ack_sequence=ack_seq,
            payload_length=len(payload),
            timestamp=int(time.time()),
        )

        # Compute HMAC over header (without auth_tag slot) + payload
        raw_header = header.encode()[:PacketHeader.SIZE]
        auth_tag = self._make_auth_tag(raw_header + payload)
        header.auth_tag = auth_tag

        datagram = header.encode() + payload
        if len(datagram) > _MAX_PACKET_SIZE:
            logger.warning("Packet exceeds MTU (%d bytes), dropping.", len(datagram))
            return False

        try:
            self._sock.sendto(datagram, addr)
            peer = self.peers.get(addr)
            if peer:
                peer.bytes_sent += len(datagram)
                peer.packets_sent += 1
            return True
        except Exception as exc:
            logger.error("Send error to %s:%d — %s", *addr, exc)
            return False

    async def send_message(self, data: bytes, addr: Tuple[str, int]) -> bool:
        """High-level helper: send DATA packet."""
        return await self.send_packet(PacketType.DATA, data, addr)

    async def ping(self, addr: Tuple[str, int]) -> bool:
        """Send PING to addr."""
        return await self.send_packet(PacketType.PING, b"", addr)

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------

    async def _handle_datagram(self, data: bytes, addr: Tuple[str, int]):
        """Parse, authenticate and dispatch an incoming datagram."""
        ip = addr[0]

        # Rate limiting
        if not self.rate_limiter.allow(ip):
            logger.debug("Rate limit: dropping packet from %s", ip)
            return

        if len(data) < PacketHeader.FULL_SIZE:
            return

        # Parse header
        try:
            header = PacketHeader.decode(data)
        except (struct.error, ValueError, KeyError) as exc:
            logger.debug("Bad packet from %s: %s", addr, exc)
            return

        payload = data[PacketHeader.FULL_SIZE:]

        # Verify HMAC
        raw_header = data[:PacketHeader.SIZE]
        if not self._verify_auth_tag(raw_header + payload, header.auth_tag):
            logger.debug("Auth tag mismatch from %s", addr)
            return

        # Replay protection
        peer = self._get_or_create_peer(addr)
        if not peer.is_sequence_valid(header.sequence):
            logger.debug("Replay detected from %s (seq=%d)", addr, header.sequence)
            return
        peer.record_sequence(header.sequence)
        peer.last_seen = time.time()
        peer.bytes_received += len(data)
        peer.packets_received += 1

        await self._dispatch(header, payload, addr, peer)

    async def _dispatch(
        self,
        header: PacketHeader,
        payload: bytes,
        addr: Tuple[str, int],
        peer: PeerConnection,
    ):
        ptype = header.packet_type

        if ptype == PacketType.PING:
            await self.send_packet(PacketType.PONG, b"", addr, ack_seq=header.sequence)

        elif ptype == PacketType.PONG:
            # RTT sample
            if header.ack_sequence in peer.unacked_packets:
                _, sent_at = peer.unacked_packets.pop(header.ack_sequence)
                rtt_ms = (time.time() - sent_at) * 1000
                peer.rtt_samples.append(rtt_ms)

        elif ptype == PacketType.HELLO:
            # Network authentication token check (Layer 3 — Network Secret)
            from murnet.core.net.network_auth import verify_network_token, is_configured as _net_ok
            if _net_ok() and payload:
                try:
                    hello_data = json.loads(payload.decode("utf-8", errors="replace"))
                    _nn = hello_data.get("net_nonce")
                    _nt = hello_data.get("net_token")
                    if not _nn or not _nt:
                        return  # Missing token → reject silently
                    _nonce = bytes.fromhex(_nn)
                    _token = bytes.fromhex(_nt)
                    _ts = int(hello_data.get("timestamp", 0))
                    if not verify_network_token(_nonce, _ts, _token):
                        return  # Bad token → reject silently
                except Exception:
                    return
            was_new = not peer.handshake_complete
            peer.handshake_complete = True
            peer.is_authenticated = True
            await self.send_packet(PacketType.ACK, b"", addr, ack_seq=header.sequence)
            if was_new and self.on_peer_connected:
                await self.on_peer_connected(peer.address, addr)
            if was_new and self._connect_handlers:
                loop = asyncio.get_event_loop()
                for h in self._connect_handlers:
                    await loop.run_in_executor(None, h, peer.address, addr[0], addr[1])

        elif ptype == PacketType.DATA:
            if self.on_message:
                await self.on_message(payload, peer.address, addr)
            if self._message_handlers:
                try:
                    msg_dict = json.loads(payload.decode("utf-8", errors="replace"))
                except Exception:
                    msg_dict = {}
                loop = asyncio.get_event_loop()
                for h in self._message_handlers:
                    await loop.run_in_executor(None, h, msg_dict, addr[0], addr[1])

        elif ptype == PacketType.ACK:
            peer.unacked_packets.pop(header.ack_sequence, None)

    # ------------------------------------------------------------------
    # Peer management
    # ------------------------------------------------------------------

    def _get_or_create_peer(self, addr: Tuple[str, int]) -> PeerConnection:
        if addr not in self.peers:
            self.peers[addr] = PeerConnection(addr=addr, address=f"{addr[0]}:{addr[1]}")
        return self.peers[addr]

    async def connect(self, ip: str, port: int, address: str = "") -> bool:
        """Initiate handshake with a remote peer."""
        import time as _time
        addr = (ip, port)
        peer = self._get_or_create_peer(addr)
        if address:
            peer.address = address

        # Build HELLO payload with network token if secret is configured
        hello_payload = b""
        from murnet.core.net.network_auth import make_network_token, is_configured as _net_ok
        if _net_ok():
            import os as _os
            _nonce = _os.urandom(32)
            _ts = int(_time.time())
            _token = make_network_token(_nonce, _ts)
            hello_payload = json.dumps({
                "timestamp": _ts,
                "net_nonce": _nonce.hex(),
                "net_token": _token.hex(),
            }).encode()

        return await self.send_packet(PacketType.HELLO, hello_payload, addr)

    def register_handler(self, handler: Callable) -> None:
        """Register a sync message handler (dict, ip: str, port: int).
        Compatible with the sync Transport.register_handler() API."""
        self._message_handlers.append(handler)

    def register_connect_handler(self, handler: Callable) -> None:
        """Register a sync connection handler (address: str, ip: str, port: int)."""
        self._connect_handlers.append(handler)

    async def async_broadcast(self, payload: bytes) -> int:
        """Send *payload* as a DATA packet to all currently known peers.

        Returns the number of peers the payload was sent to.
        """
        count = 0
        for addr in list(self.peers.keys()):
            if await self.send_message(payload, addr):
                count += 1
        return count

    def broadcast(self, payload: bytes) -> int:
        """Sync wrapper around async_broadcast — schedules a future on the
        running event loop and returns immediately.  Returns 0 in all cases
        (fire-and-forget; use async_broadcast when the count matters).
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self.async_broadcast(payload))
            else:
                loop.run_until_complete(self.async_broadcast(payload))
        except RuntimeError:
            pass
        return 0

    def get_peers(self) -> list:
        now = time.time()
        return [
            {
                "address": p.address,
                "ip": p.addr[0],
                "port": p.addr[1],
                "rtt": round(p.rtt, 2),
                "is_active": (now - p.last_seen) < _PEER_TIMEOUT,
                "packets_sent": p.packets_sent,
                "packets_received": p.packets_received,
            }
            for p in self.peers.values()
        ]

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------

    async def _keepalive_loop(self):
        """Periodically PING all known peers."""
        while self._running:
            await asyncio.sleep(_KEEPALIVE_INTERVAL)
            now = time.time()
            for addr, peer in list(self.peers.items()):
                if (now - peer.last_seen) > _PEER_TIMEOUT:
                    logger.info("Peer %s timed out", addr)
                    self.peers.pop(addr, None)
                    if self.on_peer_disconnected:
                        asyncio.ensure_future(
                            self.on_peer_disconnected(peer.address, addr)
                        )
                else:
                    await self.ping(addr)

    async def _cleanup_loop(self):
        """Periodically clean rate-limiter buckets."""
        while self._running:
            await asyncio.sleep(60.0)
            self.rate_limiter.cleanup()

    # ------------------------------------------------------------------
    # Crypto helpers
    # ------------------------------------------------------------------

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return self._seq

    def _make_auth_tag(self, data: bytes) -> bytes:
        return blake2b_hash(data, key=self.hmac_key, digest_size=16)

    def _verify_auth_tag(self, data: bytes, tag: bytes) -> bool:
        expected = self._make_auth_tag(data)
        return constant_time_compare(expected, tag)
