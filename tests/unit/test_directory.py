"""
Unit tests for core/onion/directory.py — RelayInfo + RelayDirectory.
"""
import time
import pytest

from murnet.core.onion.directory import RelayDirectory, RelayInfo


# ─────────────────────────────────────────────────────────────────────────────
# RelayInfo
# ─────────────────────────────────────────────────────────────────────────────

class TestRelayInfo:

    def test_is_alive_fresh(self):
        r = RelayInfo(addr="1.2.3.4:9001", name="Guard")
        assert r.is_alive()

    def test_is_alive_expired(self):
        r = RelayInfo(addr="1.2.3.4:9001", name="Guard",
                      timestamp=time.time() - 400, ttl=300)
        assert not r.is_alive()

    def test_roundtrip_dict(self):
        r = RelayInfo(addr="1.2.3.4:9001", name="Guard", ttl=600)
        back = RelayInfo.from_dict(r.to_dict())
        assert back.addr == r.addr
        assert back.name == r.name
        assert back.ttl  == r.ttl
        assert abs(back.timestamp - r.timestamp) < 0.01

    def test_from_dict_defaults_timestamp(self):
        before = time.time()
        r = RelayInfo.from_dict({"addr": "a:1", "name": "X"})
        assert r.timestamp >= before


# ─────────────────────────────────────────────────────────────────────────────
# RelayDirectory
# ─────────────────────────────────────────────────────────────────────────────

class TestRelayDirectory:

    def _dir_with(self, n: int) -> RelayDirectory:
        d = RelayDirectory()
        for i in range(n):
            d.announce(RelayInfo(addr=f"1.2.3.4:{9000+i}", name=f"Relay{i}"))
        return d

    def test_announce_adds_entry(self):
        d = RelayDirectory()
        info = RelayInfo(addr="1.2.3.4:9001", name="Guard")
        is_new = d.announce(info)
        assert is_new is True
        assert len(d) == 1

    def test_announce_newer_replaces_old(self):
        d = RelayDirectory()
        old = RelayInfo(addr="1.2.3.4:9001", name="Guard", timestamp=1000.0)
        new = RelayInfo(addr="1.2.3.4:9001", name="Guard", timestamp=2000.0)
        d.announce(old)
        is_new = d.announce(new)
        assert is_new is True
        assert d._relays["1.2.3.4:9001"].timestamp == 2000.0

    def test_announce_older_ignored(self):
        d = RelayDirectory()
        new = RelayInfo(addr="1.2.3.4:9001", name="Guard", timestamp=2000.0)
        old = RelayInfo(addr="1.2.3.4:9001", name="Guard", timestamp=1000.0)
        d.announce(new)
        is_new = d.announce(old)
        assert is_new is False
        assert d._relays["1.2.3.4:9001"].timestamp == 2000.0

    def test_len_counts_only_alive(self):
        d = RelayDirectory()
        d.announce(RelayInfo(addr="a:1", name="alive"))
        d.announce(RelayInfo(addr="b:2", name="dead",
                             timestamp=time.time() - 400, ttl=300))
        assert len(d) == 1

    def test_alive_returns_live_only(self):
        d = RelayDirectory()
        d.announce(RelayInfo(addr="a:1", name="alive"))
        d.announce(RelayInfo(addr="b:2", name="dead",
                             timestamp=time.time() - 400, ttl=300))
        result = d.alive()
        assert len(result) == 1
        assert result[0].name == "alive"

    def test_alive_exclude(self):
        d = self._dir_with(3)
        addrs = [f"1.2.3.4:{9000+i}" for i in range(3)]
        result = d.alive(exclude=[addrs[0]])
        assert all(r.addr != addrs[0] for r in result)
        assert len(result) == 2

    def test_pick_returns_n_unique_addrs(self):
        d = self._dir_with(5)
        picked = d.pick(3)
        assert len(picked) == 3
        assert len(set(picked)) == 3   # all unique

    def test_pick_respects_exclude(self):
        d = self._dir_with(5)
        excluded = "1.2.3.4:9000"
        picked = d.pick(3, exclude=[excluded])
        assert excluded not in picked

    def test_pick_raises_if_not_enough(self):
        d = self._dir_with(2)
        with pytest.raises(RuntimeError, match="Need 3 relays"):
            d.pick(3)

    def test_pick_raises_if_empty(self):
        d = RelayDirectory()
        with pytest.raises(RuntimeError):
            d.pick(1)

    def test_repr_shows_count(self):
        d = self._dir_with(2)
        r = repr(d)
        assert "2 alive" in r

    def test_multiple_announces_different_addrs(self):
        d = RelayDirectory()
        for i in range(10):
            d.announce(RelayInfo(addr=f"host:{i}", name=f"r{i}"))
        assert len(d) == 10
