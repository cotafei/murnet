"""
Unit tests for core/vpn/socks5.py — SOCKS5 protocol handling.

Tests exercise the wire-level protocol parsing without needing a real network
connection: asyncio streams are replaced by in-memory buffers.
"""
import asyncio
import struct
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from murnet.core.vpn.socks5 import Socks5Server, _ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6

_read_address = Socks5Server._read_address


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_reader(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    return r


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class FakeWriter:
    def __init__(self):
        self.buf = b""

    def write(self, data: bytes):
        self.buf += data

    async def drain(self):
        pass

    def get_extra_info(self, key, default=None):
        return ("127.0.0.1", 9999) if key == "peername" else default

    def close(self):
        pass


# ---------------------------------------------------------------------------
# _read_address tests
# ---------------------------------------------------------------------------

class TestReadAddress:
    def test_ipv4(self):
        data = bytes([1, 2, 3, 4]) + struct.pack("!H", 8080)
        reader = make_reader(data)
        host, port = run(_read_address(reader, _ATYP_IPV4))
        assert host == "1.2.3.4"
        assert port == 8080

    def test_domain(self):
        domain = b"example.com"
        data = bytes([len(domain)]) + domain + struct.pack("!H", 443)
        reader = make_reader(data)
        host, port = run(_read_address(reader, _ATYP_DOMAIN))
        assert host == "example.com"
        assert port == 443

    def test_domain_with_port_80(self):
        domain = b"google.com"
        data = bytes([len(domain)]) + domain + struct.pack("!H", 80)
        reader = make_reader(data)
        host, port = run(_read_address(reader, _ATYP_DOMAIN))
        assert host == "google.com"
        assert port == 80

    def test_ipv6(self):
        import socket
        raw = socket.inet_pton(socket.AF_INET6, "::1")
        data = raw + struct.pack("!H", 443)
        reader = make_reader(data)
        host, port = run(_read_address(reader, _ATYP_IPV6))
        assert ":" in host
        assert port == 443

    def test_unknown_atyp_returns_empty(self):
        reader = make_reader(b"\x00\x00\x00\x00\x00\x00")
        host, port = run(_read_address(reader, 0x99))
        assert host == ""
        assert port == 0

    def test_truncated_data_returns_empty(self):
        reader = make_reader(b"\x01\x02")  # too short for IPv4
        host, port = run(_read_address(reader, _ATYP_IPV4))
        assert host == ""
        assert port == 0


# ---------------------------------------------------------------------------
# Socks5Server handshake tests
# ---------------------------------------------------------------------------

class TestSocks5Handshake:
    def _make_server(self, mock_tunnel=None):
        if mock_tunnel is None:
            mock_tunnel = MagicMock()
            mock_tunnel.connect = AsyncMock(side_effect=ConnectionError("no exit"))
        return Socks5Server(tunnel=mock_tunnel)

    def _connect_request(self, host: str, port: int) -> bytes:
        """Build a SOCKS5 CONNECT request for a domain name."""
        encoded = host.encode()
        return (
            bytes([5, 1, 0, _ATYP_DOMAIN, len(encoded)])  # VER CMD RSV ATYP LEN
            + encoded
            + struct.pack("!H", port)
        )

    def test_auth_negotiation_noauth(self):
        """Server responds with no-auth (0x00) to noauth offer."""
        srv = self._make_server()
        # auth request + connect request (will fail at tunnel level)
        data = (
            bytes([5, 1, 0])  # VER NMETHODS NOAUTH
            + self._connect_request("example.com", 80)
        )
        reader = make_reader(data)
        writer = FakeWriter()

        run(srv._socks5_session(reader, writer))

        # First two bytes: VER=5, METHOD=0 (no-auth accepted)
        assert writer.buf[:2] == bytes([5, 0])

    def test_wrong_version_rejected(self):
        """SOCKS4 (ver=4) is silently dropped."""
        srv = self._make_server()
        reader = make_reader(bytes([4, 1, 0]))
        writer = FakeWriter()
        run(srv._socks5_session(reader, writer))
        # Nothing should be written for wrong version
        assert writer.buf == b""

    def test_unsupported_cmd_bind_returns_error(self):
        """CMD=0x02 (BIND) must get REP=0x07 (command not supported)."""
        srv = self._make_server()
        data = (
            bytes([5, 1, 0])           # auth
            + bytes([5, 2, 0, 1])      # VER CMD=BIND RSV ATYP=IPv4
            + bytes([127, 0, 0, 1])    # dst addr
            + struct.pack("!H", 80)    # dst port
        )
        reader = make_reader(data)
        writer = FakeWriter()
        run(srv._socks5_session(reader, writer))

        # Reply starts with 5, 7 (CMD_NOT_SUPPORTED)
        assert writer.buf[2:4] == bytes([5, 7])

    def test_tunnel_error_returns_connection_refused(self):
        """When tunnel.connect raises ConnectionError, reply REP=0x05."""
        tunnel = MagicMock()
        tunnel.connect = AsyncMock(side_effect=ConnectionError("no route"))
        srv = self._make_server(tunnel)

        data = bytes([5, 1, 0]) + self._connect_request("blocked.com", 80)
        reader = make_reader(data)
        writer = FakeWriter()
        run(srv._socks5_session(reader, writer))

        # Second response byte is REP — should be 0x05 (refused)
        assert writer.buf[0] == 5    # VER
        assert writer.buf[1] == 0    # no-auth accepted
        reply_start = 2
        assert writer.buf[reply_start] == 5   # VER in reply
        assert writer.buf[reply_start + 1] == 5  # REP = connection refused

    def test_successful_connect_sends_ok_reply(self):
        """When tunnel.connect succeeds, reply REP=0x00."""
        from murnet.core.vpn.tunnel import Circuit, CircuitState

        circuit = Circuit(id="c1", dst_host="example.com", dst_port=443,
                          exit_peer="ep", state=CircuitState.CONNECTED)
        circuit.connected_event.set()

        tunnel = MagicMock()
        tunnel.connect = AsyncMock(return_value=circuit)
        tunnel.send_data = AsyncMock()
        tunnel.close_circuit = MagicMock()

        srv = self._make_server(tunnel)

        # After auth+connect, simulate immediate EOF from client
        data = bytes([5, 1, 0]) + self._connect_request("example.com", 443)
        reader = make_reader(data)
        writer = FakeWriter()
        run(srv._socks5_session(reader, writer))

        # reply_start = 2 (after auth reply)
        reply_start = 2
        assert writer.buf[reply_start] == 5   # VER
        assert writer.buf[reply_start + 1] == 0  # REP = success

    def test_ipv4_connect_target(self):
        """IPv4 ATYP in CONNECT request is parsed correctly."""
        tunnel = MagicMock()
        tunnel.connect = AsyncMock(side_effect=ConnectionError("fail"))
        srv = self._make_server(tunnel)

        data = (
            bytes([5, 1, 0])
            + bytes([5, 1, 0, _ATYP_IPV4])
            + bytes([8, 8, 8, 8])
            + struct.pack("!H", 443)
        )
        reader = make_reader(data)
        writer = FakeWriter()
        run(srv._socks5_session(reader, writer))

        tunnel.connect.assert_called_once_with("8.8.8.8", 443)


# ---------------------------------------------------------------------------
# Socks5Server lifecycle
# ---------------------------------------------------------------------------

class TestSocks5ServerLifecycle:
    def test_start_stop(self):
        tunnel = MagicMock()
        srv = Socks5Server(tunnel, listen="127.0.0.1", port=0)

        async def _test():
            await srv.start()
            assert srv._server is not None
            await srv.stop()
            assert srv._server is not None  # server object remains, just closed

        run(_test())

    def test_multiple_stop_calls_safe(self):
        tunnel = MagicMock()
        srv = Socks5Server(tunnel, listen="127.0.0.1", port=0)

        async def _test():
            await srv.start()
            await srv.stop()
            await srv.stop()  # second stop should not raise

        run(_test())
