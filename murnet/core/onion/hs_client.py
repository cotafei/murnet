"""
HiddenServiceClient — резолвит .murnet адреса и проксирует HTTP-трафик.

Схема:
  browser → HTTP proxy :8888 → HiddenServiceClient
          → resolve addr.murnet → relay_addr (из directory)
          → build onion circuit → HiddenServiceRouter
          → localhost:8080 (реальный сайт)

Использование:
  client = HiddenServiceClient(transport, directory, proxy_port=8888)
  await client.start()
  # теперь в браузере: Настройки → HTTP прокси → 127.0.0.1:8888
  # открываем http://fqRQKBTR2taL9fBC7ksznZu859hs1RhQsU.murnet/
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from typing import Optional

from murnet.core.onion.router import OnionRouter
from murnet.core.onion.hidden_service import HiddenServiceDirectory

logger = logging.getLogger("murnet.hs_client")

_CONNECT_TIMEOUT = 15.0


class HiddenServiceClient:
    """
    HTTP/1.1 прокси который умеет резолвить .murnet домены.

    Обычные хосты форвардит как обычный HTTP прокси.
    .murnet хосты — через onion circuit.
    """

    def __init__(
        self,
        router: OnionRouter,
        transport,
        directory: HiddenServiceDirectory,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 8888,
    ) -> None:
        self._router    = router
        self._transport = transport
        self._directory = directory
        self._host      = proxy_host
        self._port      = proxy_port
        self._server: Optional[asyncio.Server] = None
        # relay_addr → Circuit (кешируем circuit на сервис)
        self._circuits: dict[str, object] = {}
        # sid → asyncio.Queue
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
            self._handle_request, self._host, self._port
        )
        logger.info("[hs_client] HTTP прокси на %s:%s", self._host, self._port)
        print(f"  HTTP прокси: {self._host}:{self._port}")
        print(f"  В браузере: Настройки > HTTP прокси > {self._host}:{self._port}")

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ── HTTP прокси ───────────────────────────────────────────────────────────

    async def _handle_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            # Читаем первую строку HTTP запроса
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not line:
                return

            parts = line.decode(errors="replace").strip().split()
            if len(parts) < 3:
                return

            method, url, _ = parts[0], parts[1], parts[2]

            # Читаем заголовки
            headers = {}
            while True:
                hline = await reader.readline()
                if hline in (b"\r\n", b"\n", b""):
                    break
                if b":" in hline:
                    k, v = hline.decode(errors="replace").split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            host = headers.get("host", "")
            # browsers add port: "addr.murnet:80" — strip it for the check
            host_bare = host.split(":")[0]

            if host_bare.endswith(".murnet") or ".murnet/" in url or url.endswith(".murnet"):
                await self._handle_murnet(
                    reader, writer, method, url, host_bare, headers, line
                )
            else:
                await self._handle_plain(
                    reader, writer, method, url, host, headers, line
                )

        except Exception as exc:
            logger.debug("[hs_client] request error: %s", exc)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_murnet(
        self,
        reader, writer,
        method, url, host, headers, first_line,
    ) -> None:
        addr = host if host.endswith(".murnet") else url.split("/")[2].split(":")[0]
        # browsers lowercase domain names — normalize for lookup
        relay = self._directory.resolve(addr.lower())
        if not relay:
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                b"<h1>502 Not Found</h1>"
                b"<p>MurNet: address not in directory. Service may not be announced yet.</p>"
            )
            await writer.drain()
            return

        # Строим или берём кешированный circuit
        circuit = self._circuits.get(relay)
        if not circuit:
            hops = [self._transport.resolve(h) for h in relay.split(",")]
            try:
                circuit = await asyncio.wait_for(
                    self._router.build_circuit(hops), _CONNECT_TIMEOUT
                )
                self._circuits[relay] = circuit
                logger.info("[hs_client] circuit к %s готов", addr)
            except Exception as exc:
                writer.write(
                    f"HTTP/1.1 503 Service Unavailable\r\n\r\n"
                    f"<h1>503</h1><p>Circuit failed: {exc}</p>".encode()
                )
                await writer.drain()
                return

        # Открываем hs-сессию
        sid       = str(uuid.uuid4())
        stream_id = f"hs:{sid[:8]}"
        queue: asyncio.Queue = asyncio.Queue()
        self._queues[sid] = queue

        connect_msg = json.dumps({"type": "hs_connect", "sid": sid}).encode()
        await self._router.send_data(circuit, stream_id, connect_msg)

        try:
            resp = await asyncio.wait_for(queue.get(), timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            writer.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            await writer.drain()
            return

        if resp.get("type") != "hs_connected":
            writer.write(
                f"HTTP/1.1 502 Bad Gateway\r\n\r\n{resp}".encode()
            )
            await writer.drain()
            return

        # Пересылаем HTTP запрос через circuit
        body_start = first_line + b"".join(
            f"{k}: {v}\r\n".encode() for k, v in headers.items()
        ) + b"\r\n"

        data_msg = json.dumps({
            "type": "hs_data",
            "sid":  sid,
            "data": base64.b64encode(body_start).decode(),
        }).encode()
        await self._router.send_data(circuit, stream_id, data_msg)

        # Пайпим оставшийся body и ответ
        t1 = asyncio.create_task(self._pipe_request(reader, circuit, stream_id, sid))
        t2 = asyncio.create_task(self._pipe_response(writer, queue, sid))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

        self._queues.pop(sid, None)

    async def _pipe_request(self, reader, circuit, stream_id, sid) -> None:
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                msg = json.dumps({
                    "type": "hs_data",
                    "sid":  sid,
                    "data": base64.b64encode(chunk).decode(),
                }).encode()
                await self._router.send_data(circuit, stream_id, msg)
        finally:
            close = json.dumps({"type": "hs_close", "sid": sid}).encode()
            try:
                await self._router.send_data(circuit, stream_id, close)
            except Exception:
                pass

    async def _pipe_response(self, writer, queue, sid) -> None:
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=60)
                t = msg.get("type", "")
                if t == "hs_data":
                    writer.write(base64.b64decode(msg.get("data", "")))
                    await writer.drain()
                elif t == "hs_close":
                    break
        except (asyncio.TimeoutError, Exception):
            pass

    async def _handle_plain(
        self, reader, writer, method, url, host, headers, first_line
    ) -> None:
        writer.write(
            b"HTTP/1.1 501 Not Implemented\r\n\r\n"
            b"<h1>MurNet Proxy</h1>"
            b"<p>This proxy handles only <b>.murnet</b> addresses.</p>"
        )
        await writer.drain()
