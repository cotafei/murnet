"""
Unit tests for core/vpn/config.py — VPN config parsing.
"""
import json
import os
import tempfile
import pytest
from murnet.core.vpn.config import VPNConfig, Inbound, Outbound, MurnetPeer, RoutingRule, _is_private


MINIMAL_CLIENT = {
    "inbounds": [
        {"protocol": "socks", "listen": "127.0.0.1", "port": 1080,
         "settings": {"auth": "noauth", "udp": True}, "tag": "socks"}
    ],
    "outbounds": [
        {"protocol": "murnet",
         "settings": {"peers": [{"address": "1.2.3.4", "port": 8888, "id": "abc123"}]},
         "tag": "proxy"},
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
    ],
    "murnet": {"port": 8889, "dataDir": "/tmp/vpn-test"},
}

MINIMAL_SERVER = {
    "inbounds": [],
    "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    "murnet": {"port": 8888, "dataDir": "/tmp/vpn-server", "exitMode": True},
}


class TestInboundParsing:
    def test_socks_inbound(self):
        ib = Inbound.from_dict({"protocol": "socks", "listen": "127.0.0.1",
                                "port": 1080, "tag": "socks"})
        assert ib.protocol == "socks"
        assert ib.listen == "127.0.0.1"
        assert ib.port == 1080
        assert ib.tag == "socks"

    def test_defaults(self):
        ib = Inbound.from_dict({"protocol": "socks", "port": 1080})
        assert ib.listen == "127.0.0.1"
        assert ib.tag == ""

    def test_settings_preserved(self):
        ib = Inbound.from_dict({"protocol": "socks", "port": 1080,
                                "settings": {"auth": "noauth", "udp": True}})
        assert ib.settings["auth"] == "noauth"
        assert ib.settings["udp"] is True


class TestOutboundParsing:
    def test_murnet_protocol(self):
        ob = Outbound.from_dict({"protocol": "murnet", "tag": "proxy",
                                  "settings": {"peers": [{"address": "10.0.0.1", "port": 8888}]}})
        assert ob.protocol == "murnet"
        assert ob.tag == "proxy"

    def test_freedom_protocol(self):
        ob = Outbound.from_dict({"protocol": "freedom", "tag": "direct"})
        assert ob.protocol == "freedom"

    def test_blackhole_protocol(self):
        ob = Outbound.from_dict({"protocol": "blackhole", "tag": "block"})
        assert ob.protocol == "blackhole"

    def test_murnet_peers(self):
        ob = Outbound.from_dict({
            "protocol": "murnet",
            "settings": {"peers": [
                {"address": "1.2.3.4", "port": 8888, "id": "deadbeef"},
                {"address": "5.6.7.8", "port": 9999},
            ]},
        })
        peers = ob.murnet_peers()
        assert len(peers) == 2
        assert peers[0].address == "1.2.3.4"
        assert peers[0].port == 8888
        assert peers[0].id == "deadbeef"
        assert peers[1].port == 9999
        assert peers[1].id == ""

    def test_empty_peers(self):
        ob = Outbound.from_dict({"protocol": "murnet", "settings": {}})
        assert ob.murnet_peers() == []


class TestVPNConfig:
    def test_from_dict_client(self):
        cfg = VPNConfig.from_dict(MINIMAL_CLIENT)
        assert len(cfg.inbounds) == 1
        assert len(cfg.outbounds) == 3
        assert cfg.node_port == 8889
        assert cfg.node_data_dir == "/tmp/vpn-test"
        assert cfg.exit_mode is False

    def test_from_dict_server(self):
        cfg = VPNConfig.from_dict(MINIMAL_SERVER)
        assert len(cfg.inbounds) == 0
        assert cfg.node_port == 8888
        assert cfg.exit_mode is True

    def test_default_outbound(self):
        cfg = VPNConfig.from_dict(MINIMAL_CLIENT)
        ob = cfg.default_outbound()
        assert ob is not None
        assert ob.protocol == "murnet"

    def test_outbound_by_tag(self):
        cfg = VPNConfig.from_dict(MINIMAL_CLIENT)
        assert cfg.outbound_by_tag("proxy").protocol == "murnet"
        assert cfg.outbound_by_tag("direct").protocol == "freedom"
        assert cfg.outbound_by_tag("block").protocol == "blackhole"
        assert cfg.outbound_by_tag("nonexistent") is None

    def test_load_from_file(self, tmp_path):
        p = tmp_path / "test.json"
        p.write_text(json.dumps(MINIMAL_CLIENT), encoding="utf-8")
        cfg = VPNConfig.load(p)
        assert cfg.node_port == 8889

    def test_missing_murnet_section_uses_defaults(self):
        data = {"inbounds": [], "outbounds": []}
        cfg = VPNConfig.from_dict(data)
        assert cfg.node_port == 8888
        assert cfg.node_data_dir == "~/.murnet-vpn"
        assert cfg.exit_mode is False


class TestRoutingRules:
    def test_domain_rule_parsed(self):
        data = {
            **MINIMAL_CLIENT,
            "routing": {
                "rules": [
                    {"type": "field", "domain": ["ads.example.com"],
                     "outboundTag": "block"},
                ]
            },
        }
        cfg = VPNConfig.from_dict(data)
        assert len(cfg.rules) == 1
        assert cfg.rules[0].domain == ["ads.example.com"]
        assert cfg.rules[0].outbound_tag == "block"

    def test_resolve_outbound_domain_match(self):
        data = {
            **MINIMAL_CLIENT,
            "routing": {
                "rules": [
                    {"type": "field", "domain": ["example.com"], "outboundTag": "block"},
                ]
            },
        }
        cfg = VPNConfig.from_dict(data)
        ob = cfg.resolve_outbound("ads.example.com", 80)
        assert ob.tag == "block"

    def test_resolve_outbound_private_ip(self):
        data = {
            **MINIMAL_CLIENT,
            "routing": {
                "rules": [
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                ]
            },
        }
        cfg = VPNConfig.from_dict(data)
        ob = cfg.resolve_outbound("192.168.1.1", 80)
        assert ob.tag == "direct"

    def test_resolve_outbound_falls_back_to_first(self):
        cfg = VPNConfig.from_dict(MINIMAL_CLIENT)
        ob = cfg.resolve_outbound("8.8.8.8", 53)
        assert ob.tag == "proxy"


class TestIsPrivate:
    def test_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_rfc1918(self):
        assert _is_private("10.0.0.1") is True
        assert _is_private("192.168.1.1") is True
        assert _is_private("172.16.0.1") is True

    def test_public(self):
        assert _is_private("8.8.8.8") is False
        assert _is_private("1.1.1.1") is False

    def test_localhost_string(self):
        assert _is_private("localhost") is True

    def test_domain_not_private(self):
        assert _is_private("google.com") is False
