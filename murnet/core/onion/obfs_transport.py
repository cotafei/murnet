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
import time
from collections import deque
from typing import Deque, Dict, Optional

from murnet.core.onion.cell      import OnionCell, is_onion_cell
from murnet.core.onion.directory import RelayDirectory, RelayInfo
from murnet.core.onion.router    import OnionRouter
from murnet.core.onion.transport import OnionTransport, _CONN_TIMEOUT, _RETRY_ATTEMPTS, _RETRY_DELAY
from murnet.core.onion.obfs      import ObfsStream

logger = logging.getLogger("murnet.obfs_transport")

_ANNOUNCE_EVERY = 30.0
_ANNOUNCE_TTL   = 4

# F4 rate-limit: per-IP connection rate before handshake.
# Защищает Guard/Middle/HS от X25519 CPU exhaustion.
_RL_WINDOW_S         = 10.0    # окно наблюдения, сек
_RL_MAX_CONN         = 30      # макс. новых коннектов от одного IP в окне
_RL_BAN_S            = 60.0    # пауза после превышения лимита
_RL_MAX_TRACKED_IPS  = 50_000  # hard cap чтобы не съесть RAM на botnet
_RL_GC_INTERVAL_S    = 60.0    # как часто чистим записи без активности

# C1: replay-protection nonce cache.
_NONCE_TTL_S         = 300.0   # nonce помним 5 минут (timestamp/clock-skew)
_NONCE_CACHE_CAP     = 200_000 # hard cap; LRU eviction при переполнении


# Custom exceptions для надёжной классификации probe vs other (W3).
class HandshakeProbeError(ConnectionError):
    """Failed handshake from an unauthenticated peer — likely a probe/scan."""


class ObfsTransport(OnionTransport):
    """
    OnionTransport с обфускацией.

    Все TCP-соединения проходят через ObfsStream:
      - X25519 handshake при подключении
      - ChaCha20-Poly1305 на каждый фрейм
      - Случайный padding
    """

    def __init__(
        self,
        router: OnionRouter,
        bind_host: str,
        bind_port: int,
        peers: Optional[Dict[str, str]] = None,
        self_name: Optional[str] = None,
        psk: Optional[bytes] = None,
        sni: str = "vk.com",
    ) -> None:
        super().__init__(router, bind_host, bind_port, peers, self_name)
        self.psk = psk
        self.sni = sni
        # addr / peer_id → ObfsStream
        self._obfs: Dict[str, ObfsStream] = {}
        self.probes_rejected = 0

        # F4 rate-limit state — explicit dict (no defaultdict surprise — W4).
        self._conn_history: Dict[str, Deque[float]] = {}
        self._banned_until: Dict[str, float]        = {}
        self.rate_limited = 0   # observability counter

        # C1: replay-protection — track seen handshake nonces (server-side).
        # Key = client_nonce bytes, value = first-seen monotonic timestamp.
        self._seen_nonces: Dict[bytes, float] = {}
        self.replays_rejected = 0

        # GC task для C2/N5 cleanup (запускается в start()).
        self._gc_task: Optional[asyncio.Task] = None

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        await super().start()
        # C2 fix: запускаем GC чтобы _conn_history и _seen_nonces не росли вечно.
        if self._gc_task is None or self._gc_task.done():
            self._gc_task = asyncio.create_task(self._gc_loop())

    async def stop(self) -> None:
        if self._gc_task and not self._gc_task.done():
            self._gc_task.cancel()
        await super().stop()

    # ── incoming ──────────────────────────────────────────────────────────

    async def _on_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_id = f"{peer[0]}:{peer[1]}"
        logger.debug("[obfs] accept %s", peer_id)

        # F4: rate-limit BEFORE handshake (X25519 ECDH is the expensive part).
        if not self._rate_limit_ok(peer[0]):
            self.rate_limited += 1
            writer.close()
            return

        stream = ObfsStream(
            reader, writer, is_server=True, psk=self.psk, sni=self.sni,
            check_nonce_fn=self._check_nonce,   # C1: server-side replay protection
        )
        try:
            await asyncio.wait_for(stream.handshake(), _CONN_TIMEOUT)
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionError) as exc:
            # W3 fix: classify by exception class, not message text.
            self.probes_rejected += 1
            logger.warning("[obfs] probe rejected from %s:%s: %s", peer[0], peer[1], exc)
            stream.close()
            return
        except Exception as exc:
            logger.debug("[obfs] handshake failed from %s: %s", peer_id, exc)
            stream.close()
            return

        self._obfs[peer_id] = stream
        asyncio.create_task(self._obfs_read_loop(peer_id, stream, writer))

    # ── F4 rate limiting + C1 replay cache + C2 GC ────────────────────────

    def _rate_limit_ok(self, ip: str) -> bool:
        """Token-bucket-style rate limit per source IP.

        Returns False if IP has exceeded _RL_MAX_CONN within the past
        _RL_WINDOW_S seconds (then IP is banned for _RL_BAN_S).

        Uses setdefault — no defaultdict surprise on read (W4).
        Hard cap _RL_MAX_TRACKED_IPS prevents memory exhaustion (C2).
        """
        now = time.monotonic()

        # ban window check
        banned = self._banned_until.get(ip)
        if banned and now < banned:
            return False
        if banned and now >= banned:
            self._banned_until.pop(ip, None)

        # Hard cap — if we're at capacity и это новый IP, отказываем безусловно.
        # Это grouchy fail-closed: при OOM-attack лучше отказать новым, чем умереть.
        if ip not in self._conn_history and len(self._conn_history) >= _RL_MAX_TRACKED_IPS:
            logger.warning("[obfs] rate-limit tracker FULL (%d IPs), refusing new %s",
                           _RL_MAX_TRACKED_IPS, ip)
            return False

        hist = self._conn_history.setdefault(ip, deque())
        cutoff = now - _RL_WINDOW_S
        while hist and hist[0] < cutoff:
            hist.popleft()

        if len(hist) >= _RL_MAX_CONN:
            self._banned_until[ip] = now + _RL_BAN_S
            logger.warning("[obfs] rate-limit ban %s for %ds (was %d conns in %.1fs)",
                           ip, int(_RL_BAN_S), len(hist), _RL_WINDOW_S)
            return False

        hist.append(now)
        return True

    def _check_nonce(self, nonce: bytes) -> bool:
        """C1: проверка handshake-nonce на replay.

        Returns False если nonce уже видели за последние _NONCE_TTL_S секунд.
        Hard cap _NONCE_CACHE_CAP с LRU eviction.
        """
        now = time.monotonic()
        if nonce in self._seen_nonces:
            self.replays_rejected += 1
            logger.warning("[obfs] replay nonce rejected")
            return False

        # При переполнении выкидываем самые старые (LRU by timestamp).
        if len(self._seen_nonces) >= _NONCE_CACHE_CAP:
            # cheap eviction: drop oldest 10% to amortize.
            drop_n = _NONCE_CACHE_CAP // 10
            for k in sorted(self._seen_nonces, key=self._seen_nonces.get)[:drop_n]:
                self._seen_nonces.pop(k, None)

        self._seen_nonces[nonce] = now
        return True

    async def _gc_loop(self) -> None:
        """Периодический cleanup _conn_history и _seen_nonces."""
        try:
            while True:
                await asyncio.sleep(_RL_GC_INTERVAL_S)
                self._gc_once()
        except asyncio.CancelledError:
            pass

    def _gc_once(self) -> None:
        now = time.monotonic()

        # 1) prune _conn_history: оставляем только записи с активностью.
        rl_cutoff = now - _RL_WINDOW_S * 2
        empty_ips = []
        for ip, hist in list(self._conn_history.items()):
            while hist and hist[0] < rl_cutoff:
                hist.popleft()
            if not hist and ip not in self._banned_until:
                empty_ips.append(ip)
        for ip in empty_ips:
            self._conn_history.pop(ip, None)

        # 2) prune _banned_until: убираем истёкшие баны.
        expired_bans = [ip for ip, until in self._banned_until.items() if until <= now]
        for ip in expired_bans:
            self._banned_until.pop(ip, None)

        # 3) prune _seen_nonces: nonces старше TTL.
        nonce_cutoff = now - _NONCE_TTL_S
        old_nonces = [n for n, t in self._seen_nonces.items() if t < nonce_cutoff]
        for n in old_nonces:
            self._seen_nonces.pop(n, None)

        if empty_ips or expired_bans or old_nonces:
            logger.debug("[obfs] gc: dropped %d ips, %d bans, %d nonces",
                         len(empty_ips), len(expired_bans), len(old_nonces))

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
                    stream = ObfsStream(reader, writer, is_server=False, psk=self.psk, sni=self.sni)
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
        from murnet.core.onion.directory import RelayInfo
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
