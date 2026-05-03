"""
HiddenServiceRouter — принимает onion-соединения и форвардит на localhost:port.

Схема:
  Клиент строит circuit → Exit relay → HiddenServiceRouter → localhost:8080
  Ответ идёт обратно через circuit

Используется VpnExitRouter из vpn_onion.py как основа,
но вместо выхода в интернет — форвард только на разрешённый localhost:port.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from typing import Optional

from core.onion.router import OnionRouter
from core.onion.circuit import RelayEntry
from core.onion.hidden_service import HiddenServiceIdentity, HiddenServiceAnnounce

logger = logging.getLogger("murnet.hs_router")


class HiddenServiceRouter(OnionRouter):
    """
    OnionRouter для скрытого сервиса.

    Вместо произвольного TCP (как VpnExitRouter) — подключается
    только к localhost:service_port.  Клиент не знает реальный IP сервера.

    Параметры
    ----------
    addr        : str  — bind-адрес этого relay ("host:port")
    identity    : HiddenServiceIdentity
    service_port: int  — порт локального HTTP-сервера (напр. 8080)
    """

    def __init__(
        self,
        addr: str,
        identity: HiddenServiceIdentity,
        service_port: int = 8080,
    ) -> None:
        super().__init__(addr)
        self.identity     = identity
        self.service_port = service_port
        # sid → {"entry", "cid", "stream_id", "writer", "task"}
        self._hs_sessions: dict[str, dict] = {}

    async def _handle_exit_cmd(
        self,
        entry: RelayEntry,
        my_cid: str,
        inner: dict,
    ) -> None:
        raw = base64.b64decode(inner.get("data", ""))

        try:
            msg = json.loads(raw)
        except Exception:
            return

        stream_id = inner.get("stream_id", "")
        t = msg.get("type", "")

        if t == "hs_connect":
            await self._hs_connect(entry, my_cid, stream_id, msg)

        elif t == "hs_data":
            sid     = msg.get("sid", "")
            payload = base64.b64decode(msg.get("data", ""))
            sess    = self._hs_sessions.get(sid)
            if sess:
                try:
                    sess["writer"].write(payload)
                    await sess["writer"].drain()
                except Exception:
                    await self._hs_close(sid)

        elif t == "hs_close":
            await self._hs_close(msg.get("sid", ""))

    async def _hs_connect(
        self,
        entry: RelayEntry,
        my_cid: str,
        stream_id: str,
        msg: dict,
    ) -> None:
        sid = msg.get("sid", str(uuid.uuid4()))

        logger.info("[hs] connect sid=%s → localhost:%s", sid[:8], self.service_port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.service_port),
                timeout=5,
            )
        except Exception as exc:
            err = json.dumps({"type": "hs_error", "sid": sid, "error": str(exc)}).encode()
            await self._exit_send_back(entry, my_cid, stream_id, err)
            return

        sess = {"entry": entry, "cid": my_cid, "stream_id": stream_id, "writer": writer}
        self._hs_sessions[sid] = sess

        task = asyncio.create_task(
            self._service_to_circuit(entry, my_cid, stream_id, sid, reader)
        )
        sess["task"] = task

        ok = json.dumps({"type": "hs_connected", "sid": sid}).encode()
        await self._exit_send_back(entry, my_cid, stream_id, ok)
        logger.info("[hs] connected sid=%s", sid[:8])

    async def _service_to_circuit(
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
                    "type": "hs_data",
                    "sid":  sid,
                    "data": base64.b64encode(chunk).decode(),
                }).encode()
                await self._exit_send_back(entry, my_cid, stream_id, msg)
        except Exception as exc:
            logger.debug("[hs] service_to_circuit ended: %s", exc)
        finally:
            close = json.dumps({"type": "hs_close", "sid": sid}).encode()
            try:
                await self._exit_send_back(entry, my_cid, stream_id, close)
            except Exception:
                pass
            self._hs_sessions.pop(sid, None)

    async def _hs_close(self, sid: str) -> None:
        sess = self._hs_sessions.pop(sid, None)
        if not sess:
            return
        try:
            sess["writer"].close()
        except Exception:
            pass
        task = sess.get("task")
        if task and not task.done():
            task.cancel()
