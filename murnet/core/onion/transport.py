"""
TCP transport for OnionRouter.

Wire protocol — one JSON envelope per newline:
  {"src": "<sender_listen_addr>", "cell": <OnionCell dict>}\\n
  {"src": "<sender_listen_addr>", "announce": <RelayInfo dict>, "ttl": N}\\n

NAT traversal
-------------
Replies always go back on the SAME TCP connection the peer opened.
This means only the initiator needs a reachable address:
- Guard/Middle/Exit on VDS: need open ports  (servers)
- Alice/Bob on laptop:      only connect out (clients, NAT-friendly)

When VDS receives a cell from Alice, it replies via the existing
incoming connection — it never needs to open a new connection TO
the laptop.

Relay discovery (gossip)
------------------------
If self_name is set, the transport periodically broadcasts an ANNOUNCE
message to all connected peers.  Peers forward it with ttl-1 so the
announcement propagates through the whole network.  Alice only needs
to know one relay address; she learns the rest automatically.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Dict, Optional

from murnet.core.onion.cell import OnionCell, is_onion_cell
from murnet.core.onion.directory import RelayDirectory, RelayInfo
from murnet.core.onion.router import OnionRouter

logger = logging.getLogger("murnet.onion.transport")

_CONN_TIMEOUT    = 8.0
_RETRY_ATTEMPTS  = 8
_RETRY_DELAY     = 1.5
_ANNOUNCE_EVERY  = 30.0   # seconds between self-announcements
_ANNOUNCE_TTL    = 4      # max gossip hops


class OnionTransport:
    """
    TCP transport for OnionRouter.  NAT-friendly: replies reuse the
    incoming connection instead of opening a separate reverse connection.

    Parameters
    ----------
    router : OnionRouter
        Router whose send_fn will be replaced.
    bind_host : str
        Interface to listen on (e.g. "0.0.0.0").
    bind_port : int
        Port to listen on.
    peers : dict[str, str], optional
        Friendly name -> "host:port" for known servers.
    self_name : str, optional
        Display name advertised in gossip announcements.
        If omitted the node does not announce itself as a relay.
    """

    def __init__(
        self,
        router: OnionRouter,
        bind_host: str,
        bind_port: int,
        peers: Optional[Dict[str, str]] = None,
        self_name: Optional[str] = None,
    ) -> None:
        self.router    = router
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.peers: Dict[str, str] = dict(peers or {})
        self.self_name = self_name

        self.directory = RelayDirectory()

        self._server: Optional[asyncio.AbstractServer] = None

        # Outgoing connections opened by US:  addr -> writer
        self._out: Dict[str, asyncio.StreamWriter] = {}
        # Incoming connections opened BY PEER: src_addr -> writer
        # Used for NAT-friendly replies — write back on the same socket.
        self._inc: Dict[str, asyncio.StreamWriter] = {}

        self._lock = asyncio.Lock()
        router.send_fn = self._send

    # ── public ────────────────────────────────────────────────────────────────

    def add_peer(self, name: str, addr: str) -> None:
        self.peers[name] = addr

    def resolve(self, name: str) -> str:
        return self.peers.get(name, name)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._on_accept, self.bind_host, self.bind_port
        )
        logger.info("[%s] listening on %s:%d",
                    self.router.addr, self.bind_host, self.bind_port)

        if self.self_name:
            asyncio.create_task(self._announce_loop())

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for w in list(self._out.values()) + list(self._inc.values()):
            try:
                w.close()
            except Exception:
                pass

    # ── send ─────────────────────────────────────────────────────────────────

    async def _send(self, to_name: str, cell: OnionCell) -> None:
        to_addr = self.resolve(to_name)
        writer  = self._best_writer(to_addr) or await self._open(to_addr)
        msg     = json.dumps({"src": self.router.addr, "cell": cell.to_dict()}) + "\n"
        writer.write(msg.encode())
        await writer.drain()

    def _best_writer(self, addr: str) -> Optional[asyncio.StreamWriter]:
        """Return an existing live writer (incoming preferred over outgoing)."""
        for pool in (self._inc, self._out):
            w = pool.get(addr)
            if w and not w.is_closing():
                return w
        return None

    async def _open(self, addr: str) -> asyncio.StreamWriter:
        """Open (or reuse) an outgoing connection with retry."""
        for attempt in range(_RETRY_ATTEMPTS):
            try:
                async with self._lock:
                    w = self._out.get(addr)
                    if w is None or w.is_closing():
                        host, port_s = addr.rsplit(":", 1)
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, int(port_s)),
                            _CONN_TIMEOUT,
                        )
                        self._out[addr] = writer
                        asyncio.create_task(self._read_loop(addr, reader, None))
                    return self._out[addr]
            except (ConnectionRefusedError, OSError):
                if attempt < _RETRY_ATTEMPTS - 1:
                    logger.debug("connect %s failed (attempt %d)", addr, attempt + 1)
                    await asyncio.sleep(_RETRY_DELAY)
        raise ConnectionError(f"Cannot connect to {addr} after {_RETRY_ATTEMPTS} tries")

    # ── gossip ────────────────────────────────────────────────────────────────

    async def _announce_loop(self) -> None:
        """Periodically broadcast self as a relay to all connected peers."""
        while True:
            await asyncio.sleep(_ANNOUNCE_TTL)   # short delay before first announce
            await self._broadcast_announce(self.router.addr, self.self_name, _ANNOUNCE_TTL)
            await asyncio.sleep(_ANNOUNCE_EVERY - _ANNOUNCE_TTL)

    async def _broadcast_announce(self, addr: str, name: str, ttl: int) -> None:
        """Send an announce message to every live connected peer."""
        if ttl <= 0:
            return
        info = RelayInfo(addr=addr, name=name, timestamp=time.time())
        msg  = json.dumps({
            "src":      self.router.addr,
            "announce": info.to_dict(),
            "ttl":      ttl,
        }) + "\n"
        encoded = msg.encode()

        for pool in (self._inc, self._out):
            for w in list(pool.values()):
                if not w.is_closing():
                    try:
                        w.write(encoded)
                        await w.drain()
                    except Exception:
                        pass

    async def _handle_announce(self, src: str, data: dict, ttl: int) -> None:
        """Process an incoming announce message and optionally forward it."""
        try:
            info = RelayInfo.from_dict(data)
        except Exception:
            return

        is_new = self.directory.announce(info)
        if is_new:
            logger.debug("[%s] discovered relay %s (%s) via gossip",
                         self.router.addr, info.name, info.addr)

        # Forward to our peers if TTL allows (but don't send back to src)
        if ttl > 1:
            fwd_msg = json.dumps({
                "src":      self.router.addr,
                "announce": info.to_dict(),
                "ttl":      ttl - 1,
            }) + "\n"
            encoded = fwd_msg.encode()

            for pool in (self._inc, self._out):
                for peer_addr, w in list(pool.items()):
                    if peer_addr != src and not w.is_closing():
                        try:
                            w.write(encoded)
                            await w.drain()
                        except Exception:
                            pass

    async def _broadcast_raw(self, packet: dict) -> None:
        """Broadcast any JSON packet to all live peers (used by hidden service announce)."""
        msg = json.dumps(packet) + "\n"
        encoded = msg.encode()
        for pool in (self._inc, self._out):
            for w in list(pool.values()):
                if not w.is_closing():
                    try:
                        w.write(encoded)
                        await w.drain()
                    except Exception:
                        pass

    # ── incoming ──────────────────────────────────────────────────────────────

    async def _on_accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        logger.debug("[%s] accepted %s", self.router.addr, peer)
        asyncio.create_task(self._read_loop(f"{peer[0]}:{peer[1]}", reader, writer))

    # ── read loop ─────────────────────────────────────────────────────────────

    async def _read_loop(
        self,
        peer_id: str,
        reader: asyncio.StreamReader,
        writer: Optional[asyncio.StreamWriter],  # kept alive; None for outgoing loops
    ) -> None:
        src_addr: Optional[str] = None
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    wrapper  = json.loads(line)
                    src      = wrapper.get("src", peer_id)

                    # On the first message from an incoming connection, register
                    # the writer so we can reply back on the same socket (NAT).
                    if writer and src_addr is None:
                        src_addr = src
                        self._inc[src] = writer
                        logger.debug("[%s] registered incoming from %s",
                                     self.router.addr, src)

                    # Gossip announce
                    if "announce" in wrapper:
                        asyncio.create_task(
                            self._handle_announce(src,
                                                  wrapper["announce"],
                                                  wrapper.get("ttl", 1))
                        )
                        continue

                    # Hidden service announce
                    if "hs_announce" in wrapper:
                        if hasattr(self, "hs_directory") and self.hs_directory:
                            self.hs_directory.handle_announce(wrapper)
                        # Forward with ttl-1
                        ttl = wrapper.get("ttl", 1)
                        if ttl > 1:
                            fwd = dict(wrapper, ttl=ttl - 1,
                                       src=self.router.addr)
                            asyncio.create_task(self._broadcast_raw(fwd))
                        continue

                    cell_dict = wrapper.get("cell", {})
                    if is_onion_cell(cell_dict):
                        cell = OnionCell.from_dict(cell_dict)
                        asyncio.create_task(self.router.handle_cell(cell, src))
                    else:
                        logger.debug("non-cell from %s: %s", peer_id, line[:80])
                except json.JSONDecodeError:
                    logger.debug("bad JSON from %s", peer_id)
                except Exception:
                    logger.exception("error from %s", peer_id)
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            logger.debug("connection closed: %s", peer_id)
        finally:
            self._out.pop(peer_id, None)
            if src_addr:
                self._inc.pop(src_addr, None)
