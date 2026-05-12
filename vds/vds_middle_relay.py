"""
MurNet Middle Relay — VDS

Промежуточный onion-узел между Guard (9211) и HS (9213).
Использует тот же ObfsTransport (PSK + fake TLS), что и Guard/HS.

Запуск на VDS:
  cd /root/murnet && nohup python3 vds_middle_relay.py >/tmp/murnet_middle.log 2>&1 &
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.onion.router import OnionRouter
from core.onion.obfs_transport import ObfsTransport as OnionTransport

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s  %(message)s")

VDS_IP      = os.environ.get("VDS_IP",      "80.93.52.15")
MIDDLE_PORT = int(os.environ.get("MIDDLE_PORT", "9212"))
GUARD_PORT  = int(os.environ.get("GUARD_PORT",  "9211"))
HS_PORT     = int(os.environ.get("HS_PORT",     "9213"))


async def main() -> None:
    print("\n  MurNet Middle Relay — VDS")
    print("  " + "-" * 40)
    print(f"  Listen : {VDS_IP}:{MIDDLE_PORT}")
    print(f"  Guard  : {VDS_IP}:{GUARD_PORT}")
    print(f"  HS     : {VDS_IP}:{HS_PORT}")

    router = OnionRouter(f"{VDS_IP}:{MIDDLE_PORT}")
    transport = OnionTransport(
        router, "0.0.0.0", MIDDLE_PORT,
        peers={
            "Guard": f"{VDS_IP}:{GUARD_PORT}",
            "HS":    f"{VDS_IP}:{HS_PORT}",
        },
    )
    await transport.start()
    print("  Started. Ctrl+C to stop\n")

    while True:
        await asyncio.sleep(60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
