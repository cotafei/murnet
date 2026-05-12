"""
MurNet VPN over real onion circuit.

Клиент строит 3-хоповый circuit через Guard→Middle→VpnExit на VDS.
VpnExit открывает реальные TCP-соединения к целевым хостам и проксирует трафик.
Локально поднимается SOCKS5 прокси на 127.0.0.1:1080.

────────────────────────────────────────────────────────────────
БЫСТРЫЙ СТАРТ
────────────────────────────────────────────────────────────────

  # 1. На VDS — Guard и Middle уже запущены через vds.sh
  #    Запустить VPN exit-ноду:
  python demos/vpn_onion.py --mode exit \\
      --bind 0.0.0.0:9010 --name VpnExit

  # 2. Локально:
  python demos/vpn_onion.py --mode client \\
      --peer Guard=80.93.52.15:9001 \\
      --peer Middle=80.93.52.15:9002 \\
      --peer VpnExit=80.93.52.15:9010 \\
      --circuit Guard,Middle,VpnExit \\
      --socks 127.0.0.1:1080

  # 3. Проверка:
  curl --socks5 127.0.0.1:1080 http://example.com
  curl --socks5 127.0.0.1:1080 https://ifconfig.me  # должен вернуть IP VDS

────────────────────────────────────────────────────────────────
АРХИТЕКТУРА
────────────────────────────────────────────────────────────────

  Browser → SOCKS5:1080 → VpnClient → [onion circuit] → VpnExit → Internet
  VpnExit → [onion circuit back] → VpnClient → SOCKS5 → Browser

  Wire-protocol (поверх стандартных RELAY_DATA ячеек):
    {"type":"vpn_connect","sid":"<uuid>","host":"example.com","port":443}
    {"type":"vpn_connected","sid":"<uuid>"}
    {"type":"vpn_error","sid":"<uuid>","error":"..."}
    {"type":"vpn_data","sid":"<uuid>","data":"<base64>"}
    {"type":"vpn_close","sid":"<uuid>"}
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import struct
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from murnet.core.onion.router import OnionRouter
from murnet.core.onion.transport import OnionTransport
from murnet.core.onion.circuit import RelayEntry

logger = logging.getLogger("murnet.vpn_onion")

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(name)s %(levelname)s  %(message)s",
)

_AUTO_HOPS = 3


# ─────────────────────────────────────────────────────────────────────────────
# VPN Exit Router  (runs on VDS — intercepts RELAY_DATA at exit)
# ─────────────────────────────────────────────────────────────────────────────

class VpnExitRouter(OnionRouter):
    """
    OnionRouter subclass that acts as a VPN exit:
    instead of echoing RELAY_DATA back, it opens a real TCP connection
    to the target host and proxies traffic bidirectionally.
    """

    def __init__(self, addr: str) -> None:
        super().__init__(addr)
        # sid → {"entry": RelayEntry, "cid": str, "stream_id": str,
        #         "writer": asyncio.StreamWriter, "task": asyncio.Task}
        self._vpn_sessions: dict[str, dict] = {}

    async def _handle_exit_cmd(
        self,
        entry: RelayEntry,
        my_cid: str,
        inner: dict,
    ) -> None:
        stream_id = inner.get("stream_id", "")
        raw       = base64.b64decode(inner.get("data", ""))

        try:
            msg = json.loads(raw)
        except Exception:
            return

        msg_type = msg.get("type", "")

        if msg_type == "vpn_connect":
            await self._vpn_connect(entry, my_cid, stream_id, msg)

        elif msg_type == "vpn_data":
            sid = msg.get("sid", "")
            payload = base64.b64decode(msg.get("data", ""))
            sess = self._vpn_sessions.get(sid)
            if sess:
                try:
                    sess["writer"].write(payload)
                    await sess["writer"].drain()
                except Exception:
                    await self._vpn_close_session(sid)

        elif msg_type == "vpn_close":
            sid = msg.get("sid", "")
            await self._vpn_close_session(sid)

    async def _vpn_connect(
        self,
        entry: RelayEntry,
        my_cid: str,
        stream_id: str,
        msg: dict,
    ) -> None:
        sid  = msg.get("sid", stream_id)
        host = msg.get("host", "")
        port = int(msg.get("port", 80))

        logger.info("[exit] vpn_connect sid=%s %s:%s", sid[:8], host, port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
        except Exception as exc:
            err = json.dumps({"type": "vpn_error", "sid": sid, "error": str(exc)}).encode()
            await self._exit_send_back(entry, my_cid, stream_id, err)
            return

        sess = {
            "entry":     entry,
            "cid":       my_cid,
            "stream_id": stream_id,
            "writer":    writer,
            "task":      None,
        }
        self._vpn_sessions[sid] = sess

        # Start forwarding TCP→circuit in background
        task = asyncio.create_task(
            self._tcp_to_circuit(entry, my_cid, stream_id, sid, reader)
        )
        sess["task"] = task

        ok = json.dumps({"type": "vpn_connected", "sid": sid}).encode()
        await self._exit_send_back(entry, my_cid, stream_id, ok)
        logger.info("[exit] vpn_connected sid=%s %s:%s", sid[:8], host, port)

    async def _tcp_to_circuit(
        self,
        entry: RelayEntry,
        my_cid: str,
        stream_id: str,
        sid: str,
        reader: asyncio.StreamReader,
    ) -> None:
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                msg = json.dumps({
                    "type": "vpn_data",
                    "sid":  sid,
                    "data": base64.b64encode(chunk).decode(),
                }).encode()
                await self._exit_send_back(entry, my_cid, stream_id, msg)
        except Exception as exc:
            logger.debug("[exit] tcp_to_circuit sid=%s ended: %s", sid[:8], exc)
        finally:
            close_msg = json.dumps({"type": "vpn_close", "sid": sid}).encode()
            try:
                await self._exit_send_back(entry, my_cid, stream_id, close_msg)
            except Exception:
                pass
            self._vpn_sessions.pop(sid, None)

    async def _vpn_close_session(self, sid: str) -> None:
        sess = self._vpn_sessions.pop(sid, None)
        if not sess:
            return
        try:
            sess["writer"].close()
        except Exception:
            pass
        task = sess.get("task")
        if task and not task.done():
            task.cancel()
        logger.info("[exit] vpn_close sid=%s", sid[:8])


# ─────────────────────────────────────────────────────────────────────────────
# SOCKS5 server  (runs locally — accepts browser connections)
# ─────────────────────────────────────────────────────────────────────────────

class Socks5Proxy:
    """
    Minimal SOCKS5 server (no-auth, CONNECT only).
    Forwards connections through an onion circuit to VpnExitRouter on VDS.
    """

    def __init__(
        self,
        router: OnionRouter,
        circuit,
        listen_host: str = "127.0.0.1",
        listen_port: int = 1080,
    ) -> None:
        self._router = router
        self._circuit = circuit
        self._host = listen_host
        self._port = listen_port
        self._server: asyncio.Server | None = None
        # sid → asyncio.Queue[bytes]
        self._queues: dict[str, asyncio.Queue] = {}
        router.on_data = self._on_circuit_data

    def _on_circuit_data(self, stream_id: str, data: bytes) -> None:
        try:
            msg = json.loads(data)
            sid = msg.get("sid", "")
            q   = self._queues.get(sid)
            if q is not None:
                q.put_nowait(msg)
        except Exception:
            pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_socks5, self._host, self._port
        )
        print(f"  SOCKS5 proxy listening on {self._host}:{self._port}")
        print(f"  Test: curl --socks5 {self._host}:{self._port} http://example.com")
        print(f"        curl --socks5 {self._host}:{self._port} https://ifconfig.me")

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_socks5(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            # SOCKS5 handshake
            header = await reader.read(2)
            if len(header) < 2 or header[0] != 0x05:
                return
            n_methods = header[1]
            await reader.read(n_methods)
            writer.write(b"\x05\x00")  # no-auth
            await writer.drain()

            # CONNECT request
            req = await reader.read(4)
            if len(req) < 4 or req[1] != 0x01:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return

            atyp = req[3]
            if atyp == 0x01:   # IPv4
                raw = await reader.read(4)
                host = ".".join(str(b) for b in raw)
            elif atyp == 0x03:  # domain
                n = (await reader.read(1))[0]
                host = (await reader.read(n)).decode()
            elif atyp == 0x04:  # IPv6
                raw = await reader.read(16)
                import socket
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return

            port_b = await reader.read(2)
            port   = struct.unpack("!H", port_b)[0]

            # Send vpn_connect through circuit
            sid       = str(uuid.uuid4())
            stream_id = f"vpn:{sid[:8]}"
            queue: asyncio.Queue = asyncio.Queue()
            self._queues[sid] = queue

            connect_msg = json.dumps({
                "type": "vpn_connect",
                "sid":  sid,
                "host": host,
                "port": port,
            }).encode()

            await self._router.send_data(self._circuit, stream_id, connect_msg)

            # Wait for vpn_connected / vpn_error
            try:
                resp = await asyncio.wait_for(queue.get(), timeout=15)
            except asyncio.TimeoutError:
                writer.write(b"\x05\x04\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return

            if resp.get("type") != "vpn_connected":
                err = resp.get("error", "connection refused")
                logger.warning("vpn_connect failed: %s", err)
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return

            # SOCKS5 success
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            # Pipe local↔circuit
            t1 = asyncio.create_task(
                self._local_to_circuit(reader, sid, stream_id)
            )
            t2 = asyncio.create_task(
                self._circuit_to_local(writer, sid, stream_id, queue)
            )
            done, pending = await asyncio.wait(
                [t1, t2], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()

        except Exception as exc:
            logger.debug("socks5 session error: %s", exc)
        finally:
            self._queues.pop(sid, None)
            try:
                writer.close()
            except Exception:
                pass

    async def _local_to_circuit(
        self, reader: asyncio.StreamReader, sid: str, stream_id: str
    ) -> None:
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                msg = json.dumps({
                    "type": "vpn_data",
                    "sid":  sid,
                    "data": base64.b64encode(chunk).decode(),
                }).encode()
                await self._router.send_data(self._circuit, stream_id, msg)
        finally:
            close = json.dumps({"type": "vpn_close", "sid": sid}).encode()
            try:
                await self._router.send_data(self._circuit, stream_id, close)
            except Exception:
                pass

    async def _circuit_to_local(
        self,
        writer: asyncio.StreamWriter,
        sid: str,
        stream_id: str,
        queue: asyncio.Queue,
    ) -> None:
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=120)
                t = msg.get("type", "")
                if t == "vpn_data":
                    chunk = base64.b64decode(msg.get("data", ""))
                    writer.write(chunk)
                    await writer.drain()
                elif t == "vpn_close":
                    break
        except (asyncio.TimeoutError, Exception):
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Run modes
# ─────────────────────────────────────────────────────────────────────────────

async def run_exit(args: argparse.Namespace) -> None:
    host, port = args.bind.rsplit(":", 1)
    addr = f"{host}:{port}"

    peers = {}
    for p in args.peer:
        name, paddr = p.split("=", 1)
        peers[name] = paddr

    router    = VpnExitRouter(addr)
    transport = OnionTransport(
        router, host, int(port), peers,
        self_name=args.name if args.announce else None,
    )
    await transport.start()

    print(f"[{args.name}]  VPN exit node  {addr}")
    print(f"  Onion relay + VPN exit — ready")
    print("  Ctrl+C to stop\n")

    try:
        while True:
            await asyncio.sleep(5)
            active = len(router._vpn_sessions)
            print(f"  [{args.name}]  active VPN sessions: {active}")
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await transport.stop()
        print(f"\n[{args.name}]  stopped.")


async def run_client(args: argparse.Namespace) -> None:
    host, port = args.bind.rsplit(":", 1)
    addr       = f"{host}:{port}"

    peers = {}
    for p in args.peer:
        name, paddr = p.split("=", 1)
        peers[name] = paddr

    hops = [h.strip() for h in args.circuit.split(",")]

    router    = OnionRouter(addr)
    transport = OnionTransport(router, host, int(port), peers)
    await transport.start()

    # Wait for connections to peers
    await asyncio.sleep(2)

    print(f"Building circuit: {' → '.join(hops)} …")
    resolved = [transport.resolve(h) for h in hops]

    try:
        circuit = await router.build_circuit(resolved)
    except Exception as exc:
        print(f"Circuit failed: {exc}")
        await transport.stop()
        return

    print(f"Circuit ready.")

    socks_host, socks_port = args.socks.rsplit(":", 1)
    proxy = Socks5Proxy(router, circuit, socks_host, int(socks_port))
    await proxy.start()

    print("\n  VPN is UP — configure browser/curl:")
    print(f"    curl --socks5 {socks_host}:{socks_port} http://example.com")
    print(f"    curl --socks5 {socks_host}:{socks_port} https://ifconfig.me")
    print("\n  Ctrl+C to stop\n")

    try:
        while True:
            await asyncio.sleep(10)
            print(f"  [client]  active sessions: {len(proxy._queues)}")
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await proxy.stop()
        await transport.stop()
        print("\n[client]  stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MurNet VPN over onion circuit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit (VDS):\n"
            "  python demos/vpn_onion.py --mode exit --bind 0.0.0.0:9010 --name VpnExit\n\n"
            "Client (local):\n"
            "  python demos/vpn_onion.py --mode client \\\n"
            "      --peer Guard=80.93.52.15:9001 \\\n"
            "      --peer Middle=80.93.52.15:9002 \\\n"
            "      --peer VpnExit=80.93.52.15:9010 \\\n"
            "      --circuit Guard,Middle,VpnExit \\\n"
            "      --socks 127.0.0.1:1080\n"
        ),
    )
    p.add_argument("--mode", choices=["exit", "client"], required=True)
    p.add_argument("--bind",    default="127.0.0.1:9010", metavar="HOST:PORT")
    p.add_argument("--name",    default="VpnExit")
    p.add_argument("--peer",    action="append", default=[], metavar="NAME=HOST:PORT")
    p.add_argument("--circuit", default="",
                   help="Hop list for client mode: Guard,Middle,VpnExit")
    p.add_argument("--socks",   default="127.0.0.1:1080", metavar="HOST:PORT",
                   help="SOCKS5 listen address (client mode)")
    p.add_argument("--announce", action="store_true",
                   help="Announce self as relay via gossip")
    p.add_argument("--log", default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.getLogger().setLevel(args.log)
    if args.mode == "exit":
        asyncio.run(run_exit(args))
    else:
        asyncio.run(run_client(args))
