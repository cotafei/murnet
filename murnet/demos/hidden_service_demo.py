"""
MurNet Hidden Service Demo — .murnet сайт в одном процессе.

Запуск:
  python demos/hidden_service_demo.py

Что происходит:
  1. Запускаются 3 relay-ноды (Guard, Middle, HS)
  2. Поднимается микро HTTP-сервер на localhost:8181 (сам "сайт")
  3. Генерируется .murnet адрес из Ed25519 ключа
  4. Сервис анонсирует себя через gossip
  5. Поднимается HTTP-прокси на localhost:8888
  6. Адрес выводится в терминал

Как открыть сайт:
  Браузер → Настройки → HTTP прокси → 127.0.0.1:8888
  Открыть: http://<xxxx>.murnet/

  Или через curl:
  curl --proxy http://127.0.0.1:8888 http://<xxxx>.murnet/
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from murnet.core.onion.router          import OnionRouter
from murnet.core.onion.obfs_transport  import ObfsTransport as OnionTransport
from murnet.core.onion.hidden_service  import (
    HiddenServiceIdentity,
    HiddenServiceAnnounce,
    HiddenServiceDirectory,
)
from murnet.core.onion.hs_router  import HiddenServiceRouter
from murnet.core.onion.hs_client  import HiddenServiceClient

logging.basicConfig(level=logging.WARNING,
                    format="%(asctime)s %(name)s %(levelname)s  %(message)s")

# --- порты --------------------------------------------------------------------

PORT_GUARD  = 9201
PORT_MIDDLE = 9202
PORT_HS     = 9203     # hidden service relay
PORT_CLIENT = 9204     # originator (клиент)
PORT_SITE   = 8181     # локальный HTTP-сервер ("сайт")
PORT_PROXY  = 8888     # HTTP-прокси для браузера


# --- микро HTTP-сервер ("сайт") -----------------------------------------------

def _make_site_html(addr: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>MurNet Hidden Service</title>
  <style>
    body {{ font-family: monospace; background: #0d1117; color: #e6edf3;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0; }}
    .box {{ border: 1px solid #30363d; padding: 2em 3em; border-radius: 8px; }}
    h1   {{ color: #58a6ff; }}
    code {{ background: #161b22; padding: .2em .5em; border-radius: 4px; color: #7ee787; }}
  </style>
</head>
<body><div class="box">
  <h1>&#9679; MurNet Hidden Service</h1>
  <p>Ты зашёл через onion circuit. Реальный IP сервера скрыт.</p>
  <p>Адрес: <code>{addr}</code></p>
  <p>Шифрование: X25519 + AES-256-GCM</p>
  <p>Время: <code>{time.strftime("%H:%M:%S")}</code></p>
</div></body></html>"""


SITE_HTML = b""   # заполняется после генерации адреса


class _SiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = SITE_HTML
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass   # тихий режим


def start_site_server(addr: str) -> None:
    global SITE_HTML
    SITE_HTML = _make_site_html(addr).encode()
    server = HTTPServer(("127.0.0.1", PORT_SITE), _SiteHandler)
    Thread(target=server.serve_forever, daemon=True).start()


# --- main ---------------------------------------------------------------------

async def main() -> None:
    print("\n  MurNet Hidden Service Demo")
    print("  " + "-" * 40)

    # 1. Генерируем идентичность сервиса
    key_file = os.path.join(os.path.dirname(__file__), ".hs_demo.key")
    identity = HiddenServiceIdentity(key_file)
    print(f"\n  Адрес сервиса: {identity.address}")

    # 2. Запускаем локальный HTTP-сервер ("сайт")
    start_site_server(identity.address)
    print(f"  Локальный сайт: http://127.0.0.1:{PORT_SITE}/")

    # 3. Guard relay
    guard_addr = f"127.0.0.1:{PORT_GUARD}"
    guard_r    = OnionRouter(guard_addr)
    guard_t    = OnionTransport(guard_r, "127.0.0.1", PORT_GUARD)
    await guard_t.start()

    # 4. Middle relay
    mid_addr = f"127.0.0.1:{PORT_MIDDLE}"
    mid_r    = OnionRouter(mid_addr)
    mid_t    = OnionTransport(mid_r, "127.0.0.1", PORT_MIDDLE,
                               peers={"Guard": guard_addr})
    await mid_t.start()

    # 5. Hidden Service relay (принимает onion-соединения, форвардит на :8181)
    hs_addr = f"127.0.0.1:{PORT_HS}"
    hs_r    = HiddenServiceRouter(hs_addr, identity, service_port=PORT_SITE)
    hs_t    = OnionTransport(hs_r, "127.0.0.1", PORT_HS,
                              peers={"Guard":  guard_addr,
                                     "Middle": mid_addr})
    await hs_t.start()

    # 6. Клиент-оригинатор (строит circuit)
    cli_addr = f"127.0.0.1:{PORT_CLIENT}"
    cli_r    = OnionRouter(cli_addr)
    cli_t    = OnionTransport(cli_r, "127.0.0.1", PORT_CLIENT,
                               peers={"Guard":  guard_addr,
                                      "Middle": mid_addr,
                                      "HS":     hs_addr})
    await cli_t.start()

    # 7. Директория — регистрируем сервис
    #    В реальной сети это приходит через gossip.
    #    Здесь регистрируем вручную для демо, но анонс тоже запускаем.
    directory = HiddenServiceDirectory()
    cli_t.hs_directory = directory

    # Анонс сервиса через gossip (для реальной сети)
    hs_t.hs_directory = directory
    guard_t.hs_directory = directory
    mid_t.hs_directory = directory

    announce = HiddenServiceAnnounce(identity, hs_t, relay=hs_addr)
    await announce.broadcast_now()    # сразу первый анонс

    # Также регистрируем вручную (для мгновенного старта без ожидания gossip)
    directory._entries[identity.address.lower()] = {
        "pubkey":    identity.public_bytes.hex(),
        "relay":     hs_addr,
        "timestamp": time.time(),
    }

    # Пишем peers-файл чтобы murnet_browser.py мог найти этот сервис
    import json as _json
    _peers_file = os.path.join(os.path.dirname(__file__), "..", ".murnet_peers.json")
    with open(_peers_file, "w") as _f:
        _json.dump({
            "services": {
                identity.address.lower(): {
                    "pubkey":    identity.public_bytes.hex(),
                    "relay":     hs_addr,
                    "timestamp": time.time(),
                }
            }
        }, _f, indent=2)

    # 8. HTTP-прокси для браузера
    proxy = HiddenServiceClient(cli_r, cli_t, directory,
                                 proxy_port=PORT_PROXY)
    await proxy.start()

    # 9. Вывод инструкции
    print(f"\n  HTTP прокси:   127.0.0.1:{PORT_PROXY}")
    print(f"\n  {'-'*40}")
    print(f"  Открой в браузере:")
    print(f"\n    http://{identity.address}/")
    print(f"\n  Настрой HTTP прокси: 127.0.0.1:{PORT_PROXY}")
    print(f"\n  Или через curl:")
    print(f"    curl --proxy http://127.0.0.1:{PORT_PROXY} http://{identity.address}/")
    print(f"\n  {'-'*40}")
    print("  Ctrl+C для остановки\n")

    try:
        while True:
            await asyncio.sleep(10)
            sessions = len(hs_r._hs_sessions)
            dir_size = len(directory)
            print(f"  [hs] активных сессий: {sessions}  |  записей в директории: {dir_size}")
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await asyncio.gather(
            guard_t.stop(), mid_t.stop(), hs_t.stop(), cli_t.stop(),
            proxy.stop(), return_exceptions=True,
        )
        print("\n  Остановлено.")


if __name__ == "__main__":
    asyncio.run(main())
