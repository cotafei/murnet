"""
MurNet VPN client demo — SOCKS5 proxy over MurNet.

Запускает локальный SOCKS5-прокси на 127.0.0.1:1080.
Весь трафик туннелируется через указанный exit-узел MurNet.

Использование
-------------
1. Запустить exit-ноду (на VDS или другой машине):
   python demos/vpn_client.py --mode exit --bind 0.0.0.0:7000

2. Запустить client-ноду:
   python demos/vpn_client.py --mode client \
       --exit 80.93.52.15:7000 --socks 127.0.0.1:1080

3. Настроить браузер/curl использовать SOCKS5 127.0.0.1:1080:
   curl --socks5 127.0.0.1:1080 https://example.com

Схема:
  Browser → SOCKS5:1080 → TunnelManager → [MurNet P2P] → Exit → Internet
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.vpn.tunnel import TunnelManager
from core.vpn.socks5 import Socks5Server


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fake node that wires two TunnelManagers together in-process.
# In production this would be a real AsyncMurnetNode.
# ─────────────────────────────────────────────────────────────────────────────

class _FakeNode:
    """Minimal node stub for demo purposes (single-process, no real network)."""

    def __init__(self, address: str):
        self.address = address
        self.extra_handlers: dict = {}
        self._peer: "_FakeNode | None" = None

    def link(self, other: "_FakeNode") -> None:
        self._peer = other
        other._peer = self

    def send_vpn(self, to_addr: str, payload: dict) -> None:
        if self._peer and self._peer.address == to_addr:
            handler = self._peer.extra_handlers.get("vpn")
            if handler:
                asyncio.ensure_future(
                    handler(payload, self.address, "127.0.0.1", 0)
                )


# ─────────────────────────────────────────────────────────────────────────────
# Demo modes
# ─────────────────────────────────────────────────────────────────────────────

async def run_demo_local(socks_host: str, socks_port: int) -> None:
    """
    Self-contained local demo: client + exit in one process.
    No real network needed — useful for smoke-testing.
    """
    loop = asyncio.get_event_loop()

    client_node = _FakeNode("client")
    exit_node   = _FakeNode("exit-node")
    client_node.link(exit_node)

    exit_mgr   = TunnelManager(exit_node,   exit_peer=None,          exit_mode=True)
    client_mgr = TunnelManager(client_node, exit_peer="exit-node",   exit_mode=False)

    await exit_mgr.start(loop)
    await client_mgr.start(loop)

    server = Socks5Server(client_mgr, listen=socks_host, port=socks_port)
    await server.start()

    print(f"[demo]  SOCKS5 proxy listening on {socks_host}:{socks_port}")
    print(f"[demo]  Mode: local in-process (client + exit in one process)")
    print(f"[demo]  Test:  curl --socks5 {socks_host}:{socks_port} http://example.com")
    print("  Ctrl+C to stop\n")

    try:
        while True:
            await asyncio.sleep(5)
            print(f"  [client]  active circuits: {len(client_mgr._circuits)}")
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await server.stop()
        client_mgr.stop()
        exit_mgr.stop()
        print("\n[demo]  stopped.")


async def run_exit_mode(bind_addr: str) -> None:
    """Run as a VPN exit node (server side)."""
    host, port_s = bind_addr.rsplit(":", 1)
    node = _FakeNode(bind_addr)

    loop = asyncio.get_event_loop()
    mgr  = TunnelManager(node, exit_peer=None, exit_mode=True)
    await mgr.start(loop)

    print(f"[exit]  VPN exit node at {bind_addr}")
    print("  Waiting for clients…  Ctrl+C to stop\n")

    try:
        while True:
            await asyncio.sleep(5)
            print(f"  [exit]  open sockets: {len(mgr._exit_sockets)}")
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        mgr.stop()
        print("\n[exit]  stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="MurNet VPN client/exit demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Local smoke-test (client+exit in one process):\n"
            "  python demos/vpn_client.py --mode local\n\n"
            "  # Exit node on VDS:\n"
            "  python demos/vpn_client.py --mode exit --bind 0.0.0.0:7000\n"
        ),
    )
    p.add_argument(
        "--mode", choices=["local", "exit"], default="local",
        help="local = in-process demo; exit = run as exit node",
    )
    p.add_argument(
        "--bind", default="0.0.0.0:7000",
        metavar="HOST:PORT",
        help="Exit node bind address (exit mode only)",
    )
    p.add_argument(
        "--socks", default="127.0.0.1:1080",
        metavar="HOST:PORT",
        help="SOCKS5 listen address (local mode only, default: 127.0.0.1:1080)",
    )
    p.add_argument(
        "--log", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=args.log,
        format="%(asctime)s %(name)s %(levelname)s  %(message)s",
    )

    if args.mode == "local":
        socks_host, socks_port_s = args.socks.rsplit(":", 1)
        asyncio.run(run_demo_local(socks_host, int(socks_port_s)))
    elif args.mode == "exit":
        asyncio.run(run_exit_mode(args.bind))


if __name__ == "__main__":
    main()
