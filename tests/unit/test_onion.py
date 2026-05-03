"""
Unit tests for core/onion/ — cell format, hop crypto, circuit state.
"""
import base64
import json
import os
import pytest

from core.onion.cell import OnionCell, OnionCmd, is_onion_cell, ONION_VERSION
from core.onion.hop_key import (
    generate_ephemeral_keypair,
    derive_hop_key,
    hop_encrypt,
    hop_decrypt,
)
from core.onion.circuit import (
    HopState,
    CircuitOrigin,
    RelayEntry,
    CircuitManager,
)


# ──────────────────────────────────────────────────────────────────────────────
# OnionCell
# ──────────────────────────────────────────────────────────────────────────────

class TestOnionCell:

    def test_roundtrip_empty_data(self):
        cell = OnionCell(OnionCmd.CREATE, "cid-1")
        d = cell.to_dict()
        back = OnionCell.from_dict(d)
        assert back.cmd == OnionCmd.CREATE
        assert back.circuit_id == "cid-1"
        assert back.data == b""

    def test_roundtrip_with_data(self):
        payload = os.urandom(64)
        cell = OnionCell(OnionCmd.RELAY_FWD, "cid-2", payload)
        back = OnionCell.from_dict(cell.to_dict())
        assert back.data == payload

    def test_json_roundtrip(self):
        cell = OnionCell(OnionCmd.RELAY_BACK, "cid-3", b"hello")
        assert OnionCell.from_json(cell.to_json()).data == b"hello"

    def test_all_commands_encode(self):
        for cmd in OnionCmd:
            cell = OnionCell(cmd, "x")
            assert OnionCell.from_dict(cell.to_dict()).cmd == cmd

    def test_is_onion_cell_true(self):
        cell = OnionCell(OnionCmd.CREATE, "x")
        assert is_onion_cell(cell.to_dict())

    def test_is_onion_cell_false_on_garbage(self):
        assert not is_onion_cell({})
        assert not is_onion_cell({"oc_ver": 99, "cmd": "X", "cid": "y"})
        assert not is_onion_cell({"oc_ver": ONION_VERSION, "cid": "y"})  # no cmd

    def test_oc_ver_field_present(self):
        d = OnionCell(OnionCmd.DESTROY, "cid").to_dict()
        assert d["oc_ver"] == ONION_VERSION

    def test_large_payload(self):
        big = os.urandom(65_536)
        cell = OnionCell(OnionCmd.RELAY_FWD, "cid", big)
        assert OnionCell.from_dict(cell.to_dict()).data == big


# ──────────────────────────────────────────────────────────────────────────────
# Hop-key crypto
# ──────────────────────────────────────────────────────────────────────────────

class TestHopKey:

    def test_keypair_sizes(self):
        priv, pub = generate_ephemeral_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_keypairs_are_unique(self):
        pairs = [generate_ephemeral_keypair() for _ in range(5)]
        pubkeys = [p for _, p in pairs]
        assert len(set(pubkeys)) == 5  # all distinct

    def test_ecdh_symmetric(self):
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        key_ab = derive_hop_key(priv_a, pub_b)
        key_ba = derive_hop_key(priv_b, pub_a)
        assert key_ab == key_ba
        assert len(key_ab) == 32

    def test_different_pairs_different_keys(self):
        priv_a, pub_a = generate_ephemeral_keypair()
        priv_b, pub_b = generate_ephemeral_keypair()
        priv_c, pub_c = generate_ephemeral_keypair()
        assert derive_hop_key(priv_a, pub_b) != derive_hop_key(priv_a, pub_c)

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"secret message"
        ct = hop_encrypt(key, plaintext)
        assert hop_decrypt(key, ct) == plaintext

    def test_ciphertext_is_different_each_time(self):
        key = os.urandom(32)
        pt  = b"same plaintext"
        ct1 = hop_encrypt(key, pt)
        ct2 = hop_encrypt(key, pt)
        assert ct1 != ct2  # random nonce each time

    def test_wrong_key_raises(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = hop_encrypt(key1, b"data")
        with pytest.raises(Exception):
            hop_decrypt(key2, ct)

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        ct  = bytearray(hop_encrypt(key, b"data"))
        ct[-1] ^= 0xFF  # flip last byte
        with pytest.raises(Exception):
            hop_decrypt(key, bytes(ct))

    def test_short_ciphertext_raises(self):
        key = os.urandom(32)
        with pytest.raises(ValueError):
            hop_decrypt(key, b"\x00" * 10)

    def test_large_plaintext(self):
        key = os.urandom(32)
        pt  = os.urandom(1_048_576)  # 1 MB
        assert hop_decrypt(key, hop_encrypt(key, pt)) == pt


# ──────────────────────────────────────────────────────────────────────────────
# Circuit state
# ──────────────────────────────────────────────────────────────────────────────

class TestCircuitOrigin:

    def test_defaults(self):
        c = CircuitOrigin()
        assert c.depth == 0
        assert len(c.id) > 0

    def test_unique_ids(self):
        ids = {CircuitOrigin().id for _ in range(10)}
        assert len(ids) == 10

    def test_first_peer_and_cid(self):
        c = CircuitOrigin()
        c.hops.append(HopState("peer-1", "cid-1", b"\x00" * 32))
        c.hops.append(HopState("peer-2", "cid-2", b"\x01" * 32))
        assert c.first_peer == "peer-1"
        assert c.first_cid  == "cid-1"
        assert c.depth == 2


class TestCircuitManager:

    def _entry(self, up_cid="cid-1", down_cid=None):
        return RelayEntry(
            key=os.urandom(32),
            upstream_peer="orig",
            upstream_cid=up_cid,
            downstream_peer="next" if down_cid else None,
            downstream_cid=down_cid,
        )

    def test_add_and_get(self):
        cm = CircuitManager()
        e  = self._entry("cid-1")
        cm.add(e)
        assert cm.get("cid-1") is e

    def test_get_unknown_returns_none(self):
        cm = CircuitManager()
        assert cm.get("ghost") is None

    def test_len_counts_entries_not_keys(self):
        cm = CircuitManager()
        cm.add(self._entry("a", "b"))  # stored under both "a" and "b"
        assert len(cm) == 1

    def test_set_downstream(self):
        cm = CircuitManager()
        cm.add(self._entry("up-cid"))
        cm.set_downstream("up-cid", "peer-2", "down-cid")
        e = cm.get("down-cid")
        assert e is not None
        assert e.downstream_cid == "down-cid"

    def test_remove_cleans_both_keys(self):
        cm = CircuitManager()
        cm.add(self._entry("a", "b"))
        assert cm.get("a") is not None
        cm.remove("a")
        assert cm.get("a") is None
        assert cm.get("b") is None

    def test_set_downstream_unknown_raises(self):
        cm = CircuitManager()
        with pytest.raises(KeyError):
            cm.set_downstream("ghost", "peer", "cid")


# ──────────────────────────────────────────────────────────────────────────────
# _wrap_forward (originator layering logic)
# ──────────────────────────────────────────────────────────────────────────────

class TestWrapForward:

    def _make_circuit(self, n_hops: int):
        """Build a CircuitOrigin with n random keys."""
        from core.onion.router import OnionRouter
        c = CircuitOrigin()
        for i in range(n_hops):
            priv, pub = generate_ephemeral_keypair()
            priv2, _  = generate_ephemeral_keypair()
            key = derive_hop_key(priv, pub)
            c.hops.append(HopState(f"peer-{i}", f"cid-{i}", key))
        return c

    def _peel(self, circuit: CircuitOrigin, payload: bytes) -> bytes:
        """Simulate each relay peeling its layer."""
        from core.onion.router import OnionRouter
        data = payload
        for i, hop in enumerate(circuit.hops):
            data = hop_decrypt(hop.key, data)
            if i < circuit.depth - 1:
                inner = json.loads(data)
                assert inner["cmd"] == "RELAY_NEXT", f"hop {i} expected RELAY_NEXT"
                assert inner["next_cid"] == circuit.hops[i + 1].circuit_id
                data = base64.b64decode(inner["payload"])
        return data  # innermost plaintext

    def test_1_hop(self):
        from core.onion.router import OnionRouter
        r = OnionRouter("orig")
        c = self._make_circuit(1)
        r._circuit_index = {}
        cmd = json.dumps({"cmd": "RELAY_DATA", "data": "hi"}).encode()
        wrapped = r._wrap_forward(c, cmd)
        result = self._peel(c, wrapped)
        assert json.loads(result)["cmd"] == "RELAY_DATA"

    def test_3_hops(self):
        from core.onion.router import OnionRouter
        r = OnionRouter("orig")
        c = self._make_circuit(3)
        cmd = json.dumps({"cmd": "RELAY_DATA", "data": "test"}).encode()
        wrapped = r._wrap_forward(c, cmd)
        result = self._peel(c, wrapped)
        assert json.loads(result)["data"] == "test"

    def test_5_hops(self):
        from core.onion.router import OnionRouter
        r = OnionRouter("orig")
        c = self._make_circuit(5)
        cmd = json.dumps({"cmd": "RELAY_DATA", "data": "deep"}).encode()
        result = self._peel(c, r._wrap_forward(c, cmd))
        assert json.loads(result)["data"] == "deep"

    def test_each_layer_uses_correct_key(self):
        """Verify that using wrong key at any hop fails."""
        from core.onion.router import OnionRouter
        r  = OnionRouter("orig")
        c  = self._make_circuit(3)
        bad = CircuitOrigin()
        for h in c.hops:
            bad.hops.append(HopState(h.peer_addr, h.circuit_id, os.urandom(32)))

        cmd = json.dumps({"cmd": "test"}).encode()
        wrapped = r._wrap_forward(c, cmd)
        with pytest.raises(Exception):
            self._peel(bad, wrapped)
