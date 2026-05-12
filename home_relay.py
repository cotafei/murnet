"""
home_relay.py — запустить свой ноут как Middle-узел MurNet.

Это для тестов и для добавления своего вклада в mesh-сеть.
БЕЗОПАСНОСТЬ: Middle-узел не видит ни IP клиента, ни целевой сайт —
юридически нейтральная роль (в отличие от Guard и Exit).

Что делает:
  - Открывает порт 0.0.0.0:9292 для входящих connection-ов от Guard
  - Анонсирует себя в gossip-сеть (VDS Guard узнаёт о тебе автоматически)
  - Пересылает onion-cells между Guard и HS

Требования:
  1. Открытый порт 9292 на роутере (port-forwarding к твоему ноуту)
  2. Стабильный интернет (когда ноут уходит в сон — узел отваливается)

Запуск:
    python home_relay.py
    python home_relay.py --port 9292 --name "kai-home-1"
    python home_relay.py --public-ip 95.30.X.Y  # если auto-detect не работает
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))

from core.onion.router import OnionRouter
from core.onion.obfs_transport import ObfsTransport

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
)
log = logging.getLogger("home_relay")


# ── VDS bootstrap peers ───────────────────────────────────────────────────
VDS_IP    = "80.93.52.15"
VDS_GUARD = 9211
VDS_HS    = 9213


def detect_public_ip() -> str | None:
    """Узнаём свой публичный IP через внешний сервис."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip and "." in ip:
                    return ip
        except Exception:
            continue
    return None


async def main(port: int, name: str, public_ip: str | None) -> None:
    if public_ip is None:
        public_ip = detect_public_ip()
        if public_ip:
            log.info("Auto-detected public IP: %s", public_ip)
        else:
            log.warning("Не удалось определить публичный IP. Использую 0.0.0.0 — будет работать только локально/в LAN.")
            public_ip = "0.0.0.0"

    advertised_addr = f"{public_ip}:{port}"
    log.info("=" * 50)
    log.info(" MurNet Home Middle Relay")
    log.info("=" * 50)
    log.info(" Advertised:  %s", advertised_addr)
    log.info(" Listening:   0.0.0.0:%d", port)
    log.info(" Name:        %s", name)
    log.info(" Bootstrap:   %s:%d (Guard), %s:%d (HS)",
             VDS_IP, VDS_GUARD, VDS_IP, VDS_HS)
    log.info("=" * 50)

    # OnionRouter — мозг middle-узла
    router = OnionRouter(advertised_addr)

    # ObfsTransport — обфусцированный TCP с replay protection
    # self_name → gossip-анонсы (VDS Guard узнает о нас автоматически)
    transport = ObfsTransport(
        router,
        bind_host="0.0.0.0",
        bind_port=port,
        peers={
            "Guard": f"{VDS_IP}:{VDS_GUARD}",
            "HS":    f"{VDS_IP}:{VDS_HS}",
        },
        self_name=name,
    )

    await transport.start()
    log.info("✓ Middle relay started. Gossip-announcing every 30s.")
    log.info("  Чтобы тест прошёл — порт %d должен быть проброшен на роутере.", port)
    log.info("  Ctrl+C для остановки.")

    # Periodic stats
    try:
        while True:
            await asyncio.sleep(60)
            log.info(
                "[stats] probes_rejected=%d  rate_limited=%d  replays_rejected=%d  "
                "active_streams=%d  banned_ips=%d",
                transport.probes_rejected,
                transport.rate_limited,
                transport.replays_rejected,
                len(transport._obfs),
                len(transport._banned_until),
            )
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Остановка...")
        await transport.stop()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Запустить ноут как Middle-узел MurNet")
    p.add_argument("--port",      type=int, default=9292, help="Порт (default 9292)")
    p.add_argument("--name",      default=os.environ.get("USERNAME", "home-relay"),
                   help="Имя для gossip")
    p.add_argument("--public-ip", default=None,
                   help="Твой публичный IP (если auto-detect ломается)")
    args = p.parse_args()

    try:
        asyncio.run(main(args.port, args.name, args.public_ip))
    except KeyboardInterrupt:
        pass
