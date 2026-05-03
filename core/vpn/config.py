"""
MurNet VPN Configuration — Xray/V2Ray-compatible JSON format.

Supports the same inbounds/outbounds/routing structure as Xray,
with a "murnet" protocol type for the outbound.

Example (client):
    {
      "inbounds": [{"listen":"127.0.0.1","port":1080,"protocol":"socks",
                    "settings":{"auth":"noauth","udp":true},"tag":"socks"}],
      "outbounds": [
        {"protocol":"murnet","settings":{"peers":[
            {"address":"1.2.3.4","port":8888,"id":"<murnet-node-address>"}
         ]},"tag":"proxy"},
        {"protocol":"freedom","tag":"direct"},
        {"protocol":"blackhole","tag":"block"}
      ]
    }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any


@dataclass
class MurnetPeer:
    """An exit node reachable via the MurNet P2P network."""
    address: str    # IP or hostname to connect the MurNet UDP socket
    port: int       # MurNet UDP port
    id: str = ""    # MurNet node address (identity hash) for message routing


@dataclass
class Inbound:
    protocol: str           # "socks"
    listen: str = "127.0.0.1"
    port: int = 1080
    tag: str = ""
    settings: Dict[str, Any] = field(default_factory=dict)
    sniffing: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Inbound":
        return cls(
            protocol=d["protocol"],
            listen=d.get("listen", "127.0.0.1"),
            port=int(d["port"]),
            tag=d.get("tag", ""),
            settings=d.get("settings", {}),
            sniffing=d.get("sniffing", {}),
        )


@dataclass
class Outbound:
    protocol: str   # "murnet" | "freedom" | "blackhole"
    tag: str = ""
    settings: Dict[str, Any] = field(default_factory=dict)
    stream_settings: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Outbound":
        return cls(
            protocol=d["protocol"],
            tag=d.get("tag", ""),
            settings=d.get("settings", {}),
            stream_settings=d.get("streamSettings", {}),
        )

    def murnet_peers(self) -> List[MurnetPeer]:
        return [
            MurnetPeer(
                address=p["address"],
                port=int(p.get("port", 8888)),
                id=p.get("id", ""),
            )
            for p in self.settings.get("peers", [])
        ]


@dataclass
class RoutingRule:
    outbound_tag: str = "direct"
    domain: List[str] = field(default_factory=list)
    ip: List[str] = field(default_factory=list)
    port: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "RoutingRule":
        return cls(
            outbound_tag=d.get("outboundTag", "direct"),
            domain=d.get("domain", []),
            ip=d.get("ip", []),
            port=str(d.get("port", "")),
        )


@dataclass
class VPNConfig:
    inbounds: List[Inbound] = field(default_factory=list)
    outbounds: List[Outbound] = field(default_factory=list)
    rules: List[RoutingRule] = field(default_factory=list)
    # MurNet node settings
    node_port: int = 8888
    node_data_dir: str = "~/.murnet-vpn"
    # Exit node mode
    exit_mode: bool = False

    @classmethod
    def load(cls, path: str | Path) -> "VPNConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, d: dict) -> "VPNConfig":
        inbounds  = [Inbound.from_dict(i)  for i in d.get("inbounds", [])]
        outbounds = [Outbound.from_dict(o) for o in d.get("outbounds", [])]
        routing   = d.get("routing", {})
        rules     = [RoutingRule.from_dict(r) for r in routing.get("rules", [])]
        murnet    = d.get("murnet", {})
        return cls(
            inbounds=inbounds,
            outbounds=outbounds,
            rules=rules,
            node_port=int(murnet.get("port", 8888)),
            node_data_dir=murnet.get("dataDir", "~/.murnet-vpn"),
            exit_mode=bool(murnet.get("exitMode", False)),
        )

    def default_outbound(self) -> Optional[Outbound]:
        return self.outbounds[0] if self.outbounds else None

    def outbound_by_tag(self, tag: str) -> Optional[Outbound]:
        for o in self.outbounds:
            if o.tag == tag:
                return o
        return None

    def resolve_outbound(self, host: str, port: int) -> Outbound:
        """Apply routing rules to pick an outbound for (host, port)."""
        for rule in self.rules:
            # Simple IP prefix / domain suffix matching
            for domain_pattern in rule.domain:
                if host.endswith(domain_pattern.lstrip("*")):
                    ob = self.outbound_by_tag(rule.outbound_tag)
                    if ob:
                        return ob
            for ip_pattern in rule.ip:
                if ip_pattern == "geoip:private" and _is_private(host):
                    ob = self.outbound_by_tag(rule.outbound_tag)
                    if ob:
                        return ob
        # Default: first outbound
        return self.outbounds[0] if self.outbounds else Outbound(protocol="freedom", tag="direct")


def _is_private(host: str) -> bool:
    """Return True for RFC-1918 / loopback addresses."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return host in ("localhost",)
