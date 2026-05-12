"""
MurNet Proxy Daemon — самостоятельный onion-прокси без UI.

Поднимает локальный клиентский узел и HTTP-прокси на 127.0.0.1:18888.
Используется любым внешним браузером (Rust UI, или Chrome с --proxy-server).

Запуск:
    python murnet_proxy.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from core.onion.router         import OnionRouter
from core.onion.obfs_transport import ObfsTransport as OnionTransport
from core.onion.hidden_service import HiddenServiceDirectory
from core.onion.hs_client      import HiddenServiceClient

# ── VDS endpoints ─────────────────────────────────────────────────────────
PROXY_PORT  = 18888
VDS_IP      = "80.93.52.15"
VDS_GUARD   = 9211
# Middle через который пойдёт circuit. По умолчанию VDS-Middle (9212).
# Если запустил свой узел через home_node.ps1 — поставь MURNET_MIDDLE_PORT=9290
# чтобы circuit шёл через твой ноут (SSH reverse tunnel на VDS:9290).
VDS_MIDDLE  = int(os.environ.get("MURNET_MIDDLE_PORT", "9212"))
VDS_HS      = 9213
CLIENT_PORT = 18204

# Известный hidden service на VDS (peers JSON используется как fallback)
VDS_HS_ADDR = "fgsesxh6fbmktj1od9mcu9ycyo4zuzwnxf.murnet"
VDS_HS_PUB  = "eba400645db5ad46fb7081b3c785e9cf2b7d7c3ccae839c8533e99d31d3293d8"


async def run() -> None:
    print("\n  MurNet Proxy Daemon")
    print("  " + "-" * 40)
    print(f"  HTTP proxy : 127.0.0.1:{PROXY_PORT}")
    print(f"  Client     : 127.0.0.1:{CLIENT_PORT}")
    print(f"  Guard      : {VDS_IP}:{VDS_GUARD}")
    middle_via = " (через домашний узел SSH-tunnel)" if VDS_MIDDLE == 9290 else ""
    print(f"  Middle     : {VDS_IP}:{VDS_MIDDLE}{middle_via}")
    print(f"  HS         : {VDS_IP}:{VDS_HS}")

    cli_r = OnionRouter(f"127.0.0.1:{CLIENT_PORT}")
    cli_t = OnionTransport(
        cli_r, "127.0.0.1", CLIENT_PORT,
        peers={
            "Guard":  f"{VDS_IP}:{VDS_GUARD}",
            "Middle": f"{VDS_IP}:{VDS_MIDDLE}",
            "HS":     f"{VDS_IP}:{VDS_HS}",
        },
    )
    await cli_t.start()

    directory = HiddenServiceDirectory()
    cli_t.hs_directory = directory

    # Полный 3-hop circuit: Guard → Middle → HS.
    # HiddenServiceClient делает relay.split(",") → строит build_circuit(hops),
    # значит запятые = разделитель хопов. Раньше тут был только HS-адрес
    # (1-hop), Middle вообще не использовался — это была серьёзная архитектурная
    # дыра (фактически прямой proxy, не onion routing).
    directory._entries[VDS_HS_ADDR.lower()] = {
        "pubkey":    VDS_HS_PUB,
        "relay":     f"{VDS_IP}:{VDS_GUARD},{VDS_IP}:{VDS_MIDDLE},{VDS_IP}:{VDS_HS}",
        "timestamp": time.time(),
    }

    # Опционально подмешиваем services из .murnet_vds.json (если файл рядом).
    peers_file = os.path.join(os.path.dirname(__file__), ".murnet_vds.json")
    if os.path.exists(peers_file):
        import json
        try:
            data = json.load(open(peers_file))
            for addr, entry in data.get("services", {}).items():
                entry["timestamp"] = time.time()
                directory._entries[addr.lower()] = entry
        except Exception as exc:
            print(f"  ! не смог прочитать .murnet_vds.json: {exc}")

    proxy = HiddenServiceClient(cli_r, cli_t, directory, proxy_port=PROXY_PORT)
    await proxy.start()

    print(f"\n  Готов. Настрой браузер на HTTP-прокси 127.0.0.1:{PROXY_PORT}")
    print(f"  Открой:  http://{VDS_HS_ADDR}/\n")
    print("  Ctrl+C для остановки\n")

    while True:
        await asyncio.sleep(60)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n  остановлено")
