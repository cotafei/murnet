"""
STUN Binding Request client (RFC 5389) — asyncio, stdlib only.

Determines the public IP/port of this host and heuristically identifies
the NAT type by sending two binding requests from different local ports.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import struct
import time
from dataclasses import dataclass
from typing import Literal, Optional

logger = logging.getLogger("murnet.net.stun")

_MAGIC_COOKIE = 0x2112A442
_BINDING_REQ  = 0x0001
_BINDING_RESP = 0x0101
_ATTR_XOR_MAP = 0x0020
_ATTR_MAPPED  = 0x0001
_FAM_IPV4     = 0x01
_TIMEOUT      = 3.0

STUN_SERVERS: list[tuple[str, int]] = [
    ("stun.l.google.com",    19302),
    ("stun.cloudflare.com",  3478),
    ("stun.miwifi.com",      3478),
    ("stun1.l.google.com",   19302),
]

NatType = Literal["open", "cone", "symmetric", "blocked", "unknown"]


@dataclass
class StunResult:
    public_ip:   Optional[str]
    public_port: Optional[int]
    nat_type:    NatType
    latency_ms:  float


# ── wire helpers ──────────────────────────────────────────────────────────────

def _build_request() -> tuple[bytes, bytes]:
    txn_id = os.urandom(12)
    pkt = struct.pack("!HHI12s", _BINDING_REQ, 0, _MAGIC_COOKIE, txn_id)
    return pkt, txn_id


def _parse_xor_mapped(data: bytes, txn_id: bytes) -> Optional[tuple[str, int]]:
    if len(data) < 20:
        return None
    msg_type, msg_len, magic, resp_txn = struct.unpack_from("!HHI12s", data)
    if msg_type != _BINDING_RESP or magic != _MAGIC_COOKIE or resp_txn != txn_id:
        return None

    offset, end = 20, 20 + msg_len
    best_mapped: Optional[tuple[str, int]] = None
    best_xor:    Optional[tuple[str, int]] = None

    while offset + 4 <= end and offset + 4 <= len(data):
        atype, alen = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + alen > len(data):
            break

        if atype == _ATTR_XOR_MAP and alen >= 8 and data[offset + 1] == _FAM_IPV4:
            port = struct.unpack_from("!H", data, offset + 2)[0] ^ (_MAGIC_COOKIE >> 16)
            addr = struct.unpack_from("!I", data, offset + 4)[0] ^ _MAGIC_COOKIE
            best_xor = (str(ipaddress.IPv4Address(addr)), port)

        elif atype == _ATTR_MAPPED and alen >= 8 and data[offset + 1] == _FAM_IPV4:
            port = struct.unpack_from("!H", data, offset + 2)[0]
            addr = struct.unpack_from("!I", data, offset + 4)[0]
            best_mapped = (str(ipaddress.IPv4Address(addr)), port)

        offset += (alen + 3) & ~3

    return best_xor or best_mapped


# ── UDP endpoint ──────────────────────────────────────────────────────────────

class _Proto(asyncio.DatagramProtocol):
    def __init__(self, txn_id: bytes, fut: asyncio.Future) -> None:
        self._txn_id = txn_id
        self._fut    = fut

    def datagram_received(self, data: bytes, addr) -> None:
        if not self._fut.done():
            result = _parse_xor_mapped(data, self._txn_id)
            if result is not None:
                self._fut.set_result(result)

    def error_received(self, exc: Exception) -> None:
        if not self._fut.done():
            self._fut.set_exception(exc)

    def connection_lost(self, exc) -> None:
        if not self._fut.done():
            self._fut.cancel()


async def _query_once(
    server_host: str,
    server_port: int,
    local_port: int,
) -> Optional[tuple[tuple[str, int], float]]:
    """
    Send a single binding request from *local_port*.
    Returns ((public_ip, public_port), latency_ms) or None.
    """
    loop = asyncio.get_running_loop()
    pkt, txn_id = _build_request()
    fut: asyncio.Future[tuple[str, int]] = loop.create_future()

    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _Proto(txn_id, fut),
            local_addr=("0.0.0.0", local_port),
            remote_addr=(server_host, server_port),
        )
    except OSError as exc:
        logger.debug("STUN bind/connect %s:%d local %d: %s",
                     server_host, server_port, local_port, exc)
        return None

    t0 = time.monotonic()
    try:
        transport.sendto(pkt)
        addr = await asyncio.wait_for(asyncio.shield(fut), _TIMEOUT)
        latency = (time.monotonic() - t0) * 1000
        return addr, latency
    except (asyncio.TimeoutError, asyncio.CancelledError):
        return None
    except Exception as exc:
        logger.debug("STUN query error: %s", exc)
        return None
    finally:
        transport.close()
        if not fut.done():
            fut.cancel()


# ── public API ────────────────────────────────────────────────────────────────

class StunClient:
    """
    STUN client for public address + NAT-type discovery.

    NAT type heuristic (simplified RFC 3489):
      - Two requests from different local ports to the same server.
      - Same public port both times → cone (port-preserving NAT or open).
      - Different public ports → symmetric NAT.
      - No response at all → blocked.
    """

    def __init__(
        self,
        servers: Optional[list[tuple[str, int]]] = None,
    ) -> None:
        self._servers = servers or STUN_SERVERS

    async def discover(self, local_port: int) -> StunResult:
        """
        Discover public address reachable at *local_port*.

        Tries each server in order until one responds, then sends a
        second request from ``local_port + 1`` to determine NAT type.
        """
        for host, port in self._servers:
            r1 = await _query_once(host, port, local_port)
            if r1 is None:
                logger.debug("STUN %s:%d no response", host, port)
                continue

            (pub_ip, pub_port), latency = r1
            logger.info("STUN %s:%d → %s:%d (%.1f ms)",
                        host, port, pub_ip, pub_port, latency)

            # Second query from a different local port to detect symmetric NAT
            r2 = await _query_once(host, port, local_port + 1)
            if r2 is None:
                nat: NatType = "unknown"
            else:
                (_, pub_port2), _ = r2
                if pub_port2 == pub_port + 1 or pub_port2 == pub_port:
                    # Port incremented by 1 (or preserved) → cone
                    nat = "cone"
                    # If port == local_port → open (no NAT at all)
                    if pub_port == local_port:
                        nat = "open"
                else:
                    nat = "symmetric"

            return StunResult(
                public_ip=pub_ip,
                public_port=pub_port,
                nat_type=nat,
                latency_ms=latency,
            )

        logger.warning("STUN: all servers failed")
        return StunResult(
            public_ip=None,
            public_port=None,
            nat_type="blocked",
            latency_ms=0.0,
        )
