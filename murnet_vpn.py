#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MurNet VPN v1.0
Routes TCP traffic through the MurNet P2P network.

Client mode (SOCKS5 proxy → MurNet → exit node → internet):
    python murnet_vpn.py --config configs/vpn_client.json

Exit node mode (receives tunnels, connects to real destinations):
    python murnet_vpn.py --config configs/vpn_server.json

Config file format is Xray/V2Ray-compatible JSON.
See configs/vpn_client.json and configs/vpn_server.json for examples.
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.node.node import SecureMurnetNode
from core.vpn.config import VPNConfig
from core.vpn.tunnel import TunnelManager
from core.vpn.socks5 import Socks5Server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("murnet.vpn")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run(config: VPNConfig) -> None:
    loop = asyncio.get_running_loop()

    # ------------------------------------------------------------------
    # 1. Start the MurNet node (runs in its own threads)
    # ------------------------------------------------------------------
    data_dir = str(Path(config.node_data_dir).expanduser())
    node = SecureMurnetNode(data_dir=data_dir, port=config.node_port)
    node.start()
    logger.info("MurNet node started — address: %s", node.address)

    # ------------------------------------------------------------------
    # 2. Find the first murnet outbound and connect to exit peers
    # ------------------------------------------------------------------
    exit_peer_address: str | None = None

    for outbound in config.outbounds:
        if outbound.protocol == "murnet":
            for peer in outbound.murnet_peers():
                logger.info("Connecting to exit peer %s:%s ...", peer.address, peer.port)
                node.transport.connect_to(peer.address, peer.port)
                # Give the HELLO handshake time to complete
                await asyncio.sleep(2)

                # If the peer specified a MurNet node ID, use it for routing
                if peer.id:
                    exit_peer_address = peer.id
                else:
                    # Fallback: use the first connected peer's MurNet address
                    with node.transport.peers_lock:
                        for p in node.transport.peers.values():
                            if p.handshake_complete and p.address:
                                exit_peer_address = p.address
                                break

                if exit_peer_address:
                    logger.info("Exit peer MurNet address: %s", exit_peer_address[:16])
                else:
                    logger.warning("Could not determine exit peer MurNet address yet")
            break

    # ------------------------------------------------------------------
    # 3. Start the tunnel manager
    # ------------------------------------------------------------------
    tunnel = TunnelManager(
        node=node,
        exit_peer=exit_peer_address,
        exit_mode=config.exit_mode,
    )
    await tunnel.start(loop)

    # ------------------------------------------------------------------
    # 4. Start inbound servers
    # ------------------------------------------------------------------
    servers: list[Socks5Server] = []

    for inbound in config.inbounds:
        if inbound.protocol == "socks":
            srv = Socks5Server(
                tunnel=tunnel,
                listen=inbound.listen,
                port=inbound.port,
            )
            await srv.start()
            servers.append(srv)
            logger.info("SOCKS5 proxy ready on %s:%s", inbound.listen, inbound.port)

    if not servers and not config.exit_mode:
        logger.warning("No inbound listeners configured and exit_mode=false — nothing to do.")

    if config.exit_mode:
        logger.info("Exit node mode: ready to handle VPN circuits")

    # ------------------------------------------------------------------
    # 5. Run until interrupted
    # ------------------------------------------------------------------
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except (NotImplementedError, RuntimeError):
            # Windows / some envs don't support add_signal_handler
            pass

    logger.info("VPN running. Press Ctrl+C to stop.")
    await stop_event.wait()

    # ------------------------------------------------------------------
    # 6. Graceful shutdown
    # ------------------------------------------------------------------
    logger.info("Shutting down...")
    tunnel.stop()
    for srv in servers:
        await srv.stop()
    node.stop()
    logger.info("Stopped.")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="murnet_vpn",
        description="MurNet VPN — TCP tunneling over the MurNet P2P network",
    )
    p.add_argument(
        "--config", "-c",
        default="configs/vpn_client.json",
        help="Path to JSON config file (default: configs/vpn_client.json)",
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    args = p.parse_args()

    logging.getLogger().setLevel(args.log_level)

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[error] Config file not found: {config_path}")
        sys.exit(1)

    logger.info("Loading config: %s", config_path)
    config = VPNConfig.load(config_path)

    asyncio.run(run(config))


if __name__ == "__main__":
    main()
