"""
MurNet VPN — TCP tunneling over the MurNet P2P network.

Client side: SOCKS5 proxy on 127.0.0.1:1080 that routes traffic
through MurNet to a designated exit node.

Server side: exit node that receives TUNNEL_CONNECT messages,
opens real TCP connections, and relays data back.

Usage:
    python murnet_vpn.py --config configs/vpn_client.json
    python murnet_vpn.py --config configs/vpn_server.json
"""
from core.vpn.config import VPNConfig, Inbound, Outbound, MurnetPeer
from core.vpn.tunnel import TunnelManager, Circuit
from core.vpn.socks5 import Socks5Server

__all__ = [
    "VPNConfig", "Inbound", "Outbound", "MurnetPeer",
    "TunnelManager", "Circuit",
    "Socks5Server",
]
