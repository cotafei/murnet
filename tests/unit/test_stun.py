"""
Unit tests for murnet.core.net.stun — mocked UDP transport.
"""
from __future__ import annotations

import asyncio
import ipaddress
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from murnet.core.net.stun import (
    StunClient,
    StunResult,
    _build_request,
    _parse_xor_mapped,
    _MAGIC_COOKIE,
    _BINDING_RESP,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_response(txn_id: bytes, ip: str, port: int) -> bytes:
    """Build a minimal XOR-MAPPED-ADDRESS STUN Binding Response."""
    # XOR encode
    xport = port ^ (_MAGIC_COOKIE >> 16)
    xaddr = int(ipaddress.IPv4Address(ip)) ^ _MAGIC_COOKIE

    attr_body = struct.pack("!BBHI", 0x00, 0x01, xport, xaddr)  # rsv, family, port, addr
    attr = struct.pack("!HH", 0x0020, len(attr_body)) + attr_body

    msg_len = len(attr)
    header = struct.pack("!HHI12s", _BINDING_RESP, msg_len, _MAGIC_COOKIE, txn_id)
    return header + attr


# ── _parse_xor_mapped ─────────────────────────────────────────────────────────

def test_parse_valid_response():
    _, txn_id = _build_request()
    raw = _make_response(txn_id, "1.2.3.4", 54321)
    result = _parse_xor_mapped(raw, txn_id)
    assert result == ("1.2.3.4", 54321)


def test_parse_wrong_txn_id():
    _, txn_id = _build_request()
    raw = _make_response(txn_id, "1.2.3.4", 1234)
    wrong_txn = bytes(12)
    assert _parse_xor_mapped(raw, wrong_txn) is None


def test_parse_too_short():
    assert _parse_xor_mapped(b"\x00" * 10, bytes(12)) is None


def test_parse_wrong_message_type():
    _, txn_id = _build_request()
    raw = bytearray(_make_response(txn_id, "5.6.7.8", 9999))
    # Corrupt message type to Binding Request (not Response)
    struct.pack_into("!H", raw, 0, 0x0001)
    assert _parse_xor_mapped(bytes(raw), txn_id) is None


# ── StunClient.discover ───────────────────────────────────────────────────────

def _patched_query(responses: list):
    """
    Return a coroutine factory that yields successive items from *responses*.
    Each item is ((ip, port), latency_ms) or None.
    """
    call_count = [0]

    async def _mock_query_once(host, port, local_port):
        idx = call_count[0]
        call_count[0] += 1
        return responses[idx] if idx < len(responses) else None

    return _mock_query_once


@pytest.mark.asyncio
async def test_discover_cone_nat():
    """Different-but-close public ports → cone NAT (port NOT equal to local)."""
    # public port 50001 != local port 9001 → not open
    # second query returns 50001+1=50002 → port incremented by 1 → cone
    responses = [
        (("203.0.113.1", 50001), 12.5),
        (("203.0.113.1", 50002), 11.0),
    ]
    with patch("murnet.core.net.stun._query_once", side_effect=_patched_query(responses)):
        client = StunClient(servers=[("stun.test", 3478)])
        result = await client.discover(9001)

    assert result.public_ip   == "203.0.113.1"
    assert result.public_port == 50001
    assert result.nat_type    == "cone"
    assert result.latency_ms  == pytest.approx(12.5)


@pytest.mark.asyncio
async def test_discover_open_nat():
    """Public port == local port → open."""
    responses = [
        (("203.0.113.1", 9001), 5.0),
        (("203.0.113.1", 9002), 5.0),   # port incremented by 1 → cone, but public==local → open
    ]
    with patch("murnet.core.net.stun._query_once", side_effect=_patched_query(responses)):
        client = StunClient(servers=[("stun.test", 3478)])
        result = await client.discover(9001)

    assert result.nat_type == "open"


@pytest.mark.asyncio
async def test_discover_symmetric_nat():
    """Different public ports → symmetric NAT."""
    responses = [
        (("203.0.113.1", 50001), 8.0),
        (("203.0.113.1", 50099), 8.0),  # completely different port
    ]
    with patch("murnet.core.net.stun._query_once", side_effect=_patched_query(responses)):
        client = StunClient(servers=[("stun.test", 3478)])
        result = await client.discover(9001)

    assert result.nat_type    == "symmetric"
    assert result.public_ip   == "203.0.113.1"
    assert result.public_port == 50001


@pytest.mark.asyncio
async def test_discover_blocked():
    """All servers timeout → blocked."""
    async def _no_response(host, port, local_port):
        return None

    with patch("murnet.core.net.stun._query_once", side_effect=_no_response):
        client = StunClient(servers=[("stun.test", 3478)])
        result = await client.discover(9001)

    assert result.nat_type   == "blocked"
    assert result.public_ip  is None
    assert result.latency_ms == 0.0


@pytest.mark.asyncio
async def test_discover_first_server_fails_second_succeeds():
    """Falls back to second server if first gives no response."""
    call_log: list[str] = []

    async def _selective(host, port, local_port):
        call_log.append(host)
        if host == "stun.bad":
            return None
        return (("1.1.1.1", 9001), 20.0)

    with patch("murnet.core.net.stun._query_once", side_effect=_selective):
        client = StunClient(servers=[("stun.bad", 3478), ("stun.good", 3478)])
        result = await client.discover(9001)

    assert result.public_ip == "1.1.1.1"
    assert "stun.bad" in call_log
    assert "stun.good" in call_log
