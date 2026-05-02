"""
ObfsTransport — OnionTransport с обфускацией трафика.

Заменяет plaintext JSON-over-TCP на фреймированный ChaCha20-Poly1305.
API полностью совместим с OnionTransport — просто замени класс.

Использование:
    transport = ObfsTransport(router, "127.0.0.1", 9201)
    await transport.start()
    # всё остальное — как с OnionTransport

Wire-протокол:
    Handshake : 32 байта (X25519 pubkey) в каждую сторону
    Фрейм     : [4B len][12B nonce][AEAD(payload+padding)]
    Payload   : [2B data_len][data bytes][random padding 0-255B]
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, Optional

from core.onion.cell      import OnionCell, is_onion_cell
from core.onion.directory import RelayDirectory, RelayInfo
from core.onion.router    import OnionRouter
from core.onion.transport import OnionTransport, _CONN_TIMEOUT, _RETRY_ATTEMPTS, _RETRY_DELAY
from core.onion.obfs      import ObfsStream

logger = logging.getLogger("murnet.obfs_transport")

_ANNOUNCE_EVERY = 30.0
_ANNOUNCE_TTL   = 4


class ObfsTransport(OnionTransport):
    """
    OnionTransport с обфускацией.

    Все TCP-соединения проходят через ObfsStream:
      - X25519 handshake при подключении
      - ChaCha20-Poly1305 на каждый фрейм
      - Случайный padding
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # addr / peer_id → ObfsStream
        self._obfs: Dict[str, ObfsStream] = {}

    # ── incoming ──────────────────────────────────────────────────────────

    async def _on_accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        peer_id = f"{peer[0]}:{peer[1]}"
        logger.debug("[obfs] accept %s", peer_id)

        stream = ObfsStream(reader, writer, is_server=True)
        try:
            await asyncio.wait_for(stream.handshake(), _CONN_TIMEOUT)
        except Exception as exc:
            logger.debug("[obfs] handshake failed from %s: %s", peer_id, exc)
            stream.close()
            return

        self._obfs[peer_id] = stream
        asyncio.create_task(self._obfs_read_loop(peer_id, stream, writer))

    # ── outgoing ──────────────────────────────────────────────────────────

    async def _open(self, addr: str) -> asyncio.StreamWriter:
        """Open obfuscated outgoing connection."""
        for attempt in range(_RETRY_ATTEMPTS):
            try:
                async with self._lock:
                    # Reuse if stream exists and healthy
                    if addr in self._obfs and not self._obfs[addr].is_closing():
                        # Return a dummy writer — actual writes go through _obfs
                        return self._out.get(addr) or _DummyWriter()

                    host, port_s = addr.rsplit(":", 1)
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, int(port_s)),
                        _CONN_TIMEOUT,
                    )
                    stream = ObfsStream(reader, writer, is_server=False)
                    await asyncio.wait_for(stream.handshake(), _CONN_TIMEOUT)
                    self._obfs[addr] = stream
                    self._out[addr]  = writer
                    asyncio.create_task(self._obfs_read_loop(addr, stream, None))
                    logger.debug("[obfs] connected → %s", addr)
                    return writer
            except (ConnectionRefusedError, OSError):
                if attempt < _RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(_RETRY_DELAY)
        raise ConnectionError(f"ObfsTransport: cannot connect to {addr}")

    # ── send ──────────────────────────────────────────────────────────────

    async def _send(self, to_name: str, cell: OnionCell) -> None:
        to_addr = self.resolve(to_name)
        # Ensure connection exists
        await self._open(to_addr)
        stream = self._obfs.get(to_addr)
        if not stream:
            raise ConnectionError(f"No obfs stream to {to_addr}")
        msg = json.dumps({"src": self.router.addr, "cell": cell.to_dict()})
        stream.write(msg.encode())
        await stream.drain()

    # ── broadcast (gossip + hs_announce) ─────────────────────────────────

    async def _broadcast_raw(self, packet: dict) -> None:
        msg = json.dumps(packet).encode()
        for stream in list(self._obfs.values()):
            if not stream.is_closing():
                try:
                    stream.write(msg)
                    await stream.drain()
                except Exception:
                    pass

    async def _broadcast_announce(self, addr: str, name: str, ttl: int) -> None:
        import time
        from core.onion.directory import RelayInfo
        if ttl <= 0:
            return
        info = RelayInfo(addr=addr, name=name, timestamp=time.time())
        msg  = json.dumps({
            "src": self.router.addr, "announce": info.to_dict(), "ttl": ttl,
        }).encode()
        for stream in list(self._obfs.values()):
            if not stream.is_closing():
                try:
                    stream.write(msg)
                    await stream.drain()
                except Exception:
                    pass

    # ── obfs read loop ────────────────────────────────────────────────────

    async def _obfs_read_loop(
        self,
        peer_id: str,
        stream: ObfsStream,
        writer: Optional[asyncio.StreamWriter],
    ) -> None:
        src_addr: Optional[str] = None
        try:
            while True:
                raw = await stream.read()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    wrapper  = json.loads(line)
                    src      = wrapper.get("src", peer_id)

                    if writer and src_addr is None:
                        src_addr = src
                        self._inc[src]   = writer
                        self._obfs[src]  = stream
                        logger.debug("[obfs] registered incoming %s", src)

                    if "announce" in wrapper:
                        asyncio.create_task(
                            self._handle_announce(src,
                                                  wrapper["announce"],
                                                  wrapper.get("ttl", 1))
                        )
                        continue

                    if "hs_announce" in wrapper:
                        if hasattr(self, "hs_directory") and self.hs_directory:
                            self.hs_directory.handle_announce(wrapper)
                        ttl = wrapper.get("ttl", 1)
                        if ttl > 1:
                            fwd = dict(wrapper, ttl=ttl - 1, src=self.router.addr)
                            asyncio.create_task(self._broadcast_raw(fwd))
                        continue

                    cell_dict = wrapper.get("cell", {})
                    if is_onion_cell(cell_dict):
                        cell = OnionCell.from_dict(cell_dict)
                        asyncio.create_task(self.router.handle_cell(cell, src))
                    else:
                        logger.debug("[obfs] non-cell from %s", peer_id)

                except json.JSONDecodeError:
                    logger.debug("[obfs] bad JSON from %s", peer_id)
                except Exception:
                    logger.exception("[obfs] error from %s", peer_id)

        except asyncio.IncompleteReadError:
            pass
        except Exception:
            logger.debug("[obfs] connection closed: %s", peer_id)
        finally:
            self._out.pop(peer_id, None)
            self._obfs.pop(peer_id, None)
            if src_addr:
                self._inc.pop(src_addr, None)
                self._obfs.pop(src_addr, None)


class _DummyWriter:
    """Заглушка — реальная запись идёт через ObfsStream."""
    def is_closing(self): return False
    def write(self, _): pass
    async def drain(self): pass
    def close(self): pass
    def get_extra_info(self, *a): return None
