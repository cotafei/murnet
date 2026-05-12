"""
MurNet VPN — asyncio SOCKS5 server (CONNECT only, no-auth).

Each CONNECT request opens a MurNet VPN circuit to the destination.
Data is then piped bidirectionally between the local TCP socket and
the circuit's recv_queue until either side closes.

SOCKS5 wire protocol (RFC 1928):

  Handshake:
    C→S  \x05 \x01 \x00          (ver=5, 1 method, no-auth)
    S→C  \x05 \x00               (ver=5, method=no-auth)

  Request:
    C→S  \x05 \x01 \x00 ATYP DST_ADDR DST_PORT
         ATYP: 0x01=IPv4(4B) | 0x03=domain(1B+NB) | 0x04=IPv6(16B)
         DST_PORT: 2B big-endian

  Reply (success):
    S→C  \x05 \x00 \x00 \x01 \x00\x00\x00\x00 \x00\x00
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from murnet.core.vpn.tunnel import TunnelManager, Circuit

logger = logging.getLogger("murnet.vpn.socks5")

_SOCKS_VER = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4   = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6   = 0x04

_REP_OK      = 0x00
_REP_GENERAL = 0x01
_REP_REFUSED = 0x05
_REP_CMD_UNSUPPORTED = 0x07


class Socks5Server:
    """
    Async SOCKS5 server that tunnels CONNECT traffic through MurNet.

        server = Socks5Server(tunnel_manager, listen="127.0.0.1", port=1080)
        await server.start()
        ...
        await server.stop()
    """

    def __init__(
        self,
        tunnel: "TunnelManager",
        listen: str = "127.0.0.1",
        port: int = 1080,
    ):
        self.tunnel = tunnel
        self.listen = listen
        self.port = port
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.listen,
            port=self.port,
        )
        addr = self._server.sockets[0].getsockname()
        logger.info("SOCKS5 listening on %s:%s", addr[0], addr[1])

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ------------------------------------------------------------------
    # Per-connection handler
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            await self._socks5_session(reader, writer)
        except Exception as exc:
            logger.debug("SOCKS5 session error (%s): %s", peer, exc)
        finally:
            writer.close()

    async def _socks5_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # --- Auth negotiation ---
        header = await reader.readexactly(2)
        ver, nmethods = header
        if ver != _SOCKS_VER:
            return
        await reader.readexactly(nmethods)          # consume methods list
        writer.write(bytes([_SOCKS_VER, 0x00]))     # no-auth
        await writer.drain()

        # --- Request ---
        req = await reader.readexactly(4)
        ver, cmd, _, atyp = req
        if ver != _SOCKS_VER or cmd != _CMD_CONNECT:
            writer.write(bytes([_SOCKS_VER, _REP_CMD_UNSUPPORTED, 0, _ATYP_IPV4,
                                 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            return

        dst_host, dst_port = await self._read_address(reader, atyp)
        if not dst_host or not dst_port:
            writer.write(bytes([_SOCKS_VER, _REP_GENERAL, 0, _ATYP_IPV4,
                                 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            return

        logger.info("CONNECT %s:%s", dst_host, dst_port)

        # --- Open VPN circuit ---
        try:
            circuit = await self.tunnel.connect(dst_host, dst_port)
        except ConnectionError as exc:
            logger.warning("Circuit failed for %s:%s — %s", dst_host, dst_port, exc)
            writer.write(bytes([_SOCKS_VER, _REP_REFUSED, 0, _ATYP_IPV4,
                                 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            return

        # --- Success reply ---
        writer.write(bytes([_SOCKS_VER, _REP_OK, 0, _ATYP_IPV4,
                             0, 0, 0, 0, 0, 0]))
        await writer.drain()

        # --- Bidirectional relay ---
        await self._relay(reader, writer, circuit)

    async def _relay(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        circuit: "Circuit",
    ) -> None:
        """Pipe data between local TCP socket and the MurNet circuit."""
        async def local_to_tunnel():
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    await self.tunnel.send_data(circuit, data)
            except Exception:
                pass
            finally:
                self.tunnel.close_circuit(circuit)

        async def tunnel_to_local():
            try:
                while True:
                    # Wait for data from exit node
                    chunk = await asyncio.wait_for(
                        circuit.recv_queue.get(), timeout=120
                    )
                    if not chunk:   # EOF sentinel
                        break
                    writer.write(chunk)
                    await writer.drain()
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass
            finally:
                self.tunnel.close_circuit(circuit)

        await asyncio.gather(local_to_tunnel(), tunnel_to_local(),
                             return_exceptions=True)

    # ------------------------------------------------------------------
    # Address parsing
    # ------------------------------------------------------------------

    @staticmethod
    async def _read_address(
        reader: asyncio.StreamReader,
        atyp: int,
    ) -> Tuple[str, int]:
        try:
            if atyp == _ATYP_IPV4:
                raw = await reader.readexactly(4)
                host = ".".join(str(b) for b in raw)
            elif atyp == _ATYP_DOMAIN:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode()
            elif atyp == _ATYP_IPV6:
                raw = await reader.readexactly(16)
                import socket as _s
                host = _s.inet_ntop(_s.AF_INET6, raw)
            else:
                return "", 0
            port_bytes = await reader.readexactly(2)
            port = struct.unpack("!H", port_bytes)[0]
            return host, port
        except Exception:
            return "", 0
