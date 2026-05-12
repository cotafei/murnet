"""
Unit tests for MurNet v6.2 Object System and Pub/Sub Layer.

Run with:
    python -m pytest tests/unit/test_objects.py -v
"""

import asyncio
import json
import os
import tempfile
import time

import pytest

from murnet.core.data.objects import MurObject, ObjectStore, MAX_OBJECT_SIZE
from murnet.core.node.pubsub import PubSubManager, topic_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmpdir_store(tmp_path):
    """ObjectStore backed by a real temp directory."""
    return ObjectStore(str(tmp_path))


@pytest.fixture
def mem_store():
    """In-memory-only ObjectStore (persist=False)."""
    return ObjectStore(".", persist=False)


def _dummy_object(obj_type="msg", owner="1TestOwner", data=None, timestamp=None):
    """Create a signed-free MurObject for testing (no identity needed)."""
    return MurObject.create(
        obj_type=obj_type,
        owner=owner,
        data=data or {"text": "hello"},
        identity=None,
        timestamp=timestamp or 1_712_345_678.0,
    )


# ===========================================================================
# MurObject
# ===========================================================================


class TestMurObjectCreation:
    def test_create_sets_type_and_owner(self):
        obj = _dummy_object(obj_type="profile", owner="1Alice")
        assert obj.type == "profile"
        assert obj.owner == "1Alice"

    def test_id_is_64_char_hex(self):
        obj = _dummy_object()
        assert len(obj.id) == 64
        assert all(c in "0123456789abcdef" for c in obj.id)

    def test_id_deterministic(self):
        a = _dummy_object(data={"k": "v"}, timestamp=100.0)
        b = _dummy_object(data={"k": "v"}, timestamp=100.0)
        assert a.id == b.id

    def test_different_data_different_id(self):
        a = _dummy_object(data={"k": "v1"}, timestamp=100.0)
        b = _dummy_object(data={"k": "v2"}, timestamp=100.0)
        assert a.id != b.id

    def test_signature_empty_without_identity(self):
        obj = _dummy_object()
        assert obj.signature == ""


class TestMurObjectIntegrity:
    def test_verify_id_ok(self):
        obj = _dummy_object()
        assert obj.verify_id()

    def test_verify_id_fails_on_tamper(self):
        obj = _dummy_object()
        obj.data["text"] = "tampered"
        assert not obj.verify_id()

    def test_is_valid_no_pubkey(self):
        obj = _dummy_object()
        assert obj.is_valid()

    def test_is_valid_fails_on_data_tamper(self):
        obj = _dummy_object()
        obj.data["evil"] = True
        assert not obj.is_valid()


class TestMurObjectSerialization:
    def test_round_trip_dict(self):
        obj = _dummy_object()
        d = obj.to_dict()
        obj2 = MurObject.from_dict(d)
        assert obj == obj2
        assert obj2.verify_id()

    def test_round_trip_bytes(self):
        obj = _dummy_object()
        obj2 = MurObject.from_bytes(obj.to_bytes())
        assert obj == obj2

    def test_from_dict_missing_field_raises(self):
        d = _dummy_object().to_dict()
        del d["owner"]
        with pytest.raises(ValueError, match="owner"):
            MurObject.from_dict(d)

    def test_canonical_bytes_excludes_signature(self):
        obj = _dummy_object()
        obj.signature = "fakesig"
        canon = json.loads(obj.canonical_bytes().decode())
        assert "signature" not in canon

    def test_canonical_bytes_sorted_keys(self):
        obj = _dummy_object()
        canon = json.loads(obj.canonical_bytes().decode())
        assert list(canon.keys()) == sorted(canon.keys())

    def test_equality_by_id(self):
        obj = _dummy_object()
        obj2 = MurObject.from_bytes(obj.to_bytes())
        assert obj == obj2
        assert hash(obj) == hash(obj2)


# ===========================================================================
# ObjectStore
# ===========================================================================


class TestObjectStoreBasic:
    def test_put_and_get(self, mem_store):
        obj = _dummy_object()
        assert mem_store.put(obj)
        retrieved = mem_store.get(obj.id)
        assert retrieved == obj

    def test_put_returns_false_on_duplicate(self, mem_store):
        obj = _dummy_object()
        assert mem_store.put(obj)
        assert not mem_store.put(obj)

    def test_has_returns_true_after_put(self, mem_store):
        obj = _dummy_object()
        assert not mem_store.has(obj.id)
        mem_store.put(obj)
        assert mem_store.has(obj.id)

    def test_get_returns_none_for_unknown(self, mem_store):
        assert mem_store.get("a" * 64) is None

    def test_delete_removes_object(self, mem_store):
        obj = _dummy_object()
        mem_store.put(obj)
        assert mem_store.delete(obj.id)
        assert not mem_store.has(obj.id)

    def test_delete_nonexistent_returns_false(self, mem_store):
        assert not mem_store.delete("b" * 64)

    def test_list_ids(self, mem_store):
        o1 = _dummy_object(data={"n": 1}, timestamp=1.0)
        o2 = _dummy_object(data={"n": 2}, timestamp=2.0)
        mem_store.put(o1)
        mem_store.put(o2)
        ids = mem_store.list_ids()
        assert o1.id in ids
        assert o2.id in ids

    def test_list_by_type(self, mem_store):
        msg = _dummy_object(obj_type="msg", data={"n": 1}, timestamp=1.0)
        profile = _dummy_object(obj_type="profile", data={"n": 2}, timestamp=2.0)
        mem_store.put(msg)
        mem_store.put(profile)
        msgs = mem_store.list_by_type("msg")
        assert msg in msgs
        assert profile not in msgs

    def test_put_rejects_id_mismatch(self, mem_store):
        obj = _dummy_object()
        obj.id = "c" * 64   # corrupt id
        with pytest.raises(ValueError, match="ID mismatch"):
            mem_store.put(obj)

    def test_stats_keys(self, mem_store):
        s = mem_store.stats()
        assert "cached" in s
        assert "persist" in s


class TestObjectStorePersistence:
    def test_persists_to_disk(self, tmpdir_store, tmp_path):
        obj = _dummy_object()
        tmpdir_store.put(obj)
        # A file should exist under objects/
        prefix = obj.id[:2]
        path = tmp_path / "objects" / prefix / f"{obj.id}.json"
        assert path.exists()

    def test_load_from_disk(self, tmp_path):
        store1 = ObjectStore(str(tmp_path))
        obj = _dummy_object()
        store1.put(obj)

        # Create a second store pointing at same directory (empty cache)
        store2 = ObjectStore(str(tmp_path))
        loaded = store2.get(obj.id)
        assert loaded is not None
        assert loaded == obj

    def test_list_ids_includes_disk_objects(self, tmp_path):
        store1 = ObjectStore(str(tmp_path))
        obj = _dummy_object()
        store1.put(obj)

        store2 = ObjectStore(str(tmp_path))
        assert obj.id in store2.list_ids()


# ===========================================================================
# topic_id
# ===========================================================================


class TestTopicId:
    def test_returns_32_char_hex(self):
        tid = topic_id("room:general")
        assert len(tid) == 32
        assert all(c in "0123456789abcdef" for c in tid)

    def test_same_name_same_id(self):
        assert topic_id("alice") == topic_id("alice")

    def test_different_names_different_ids(self):
        assert topic_id("alice") != topic_id("bob")


# ===========================================================================
# PubSubManager — local (no transport)
# ===========================================================================


class TestPubSubLocal:
    def test_subscribe_and_receive(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        mgr.subscribe("news", lambda tid, obj: received.append(obj))

        obj = _dummy_object(obj_type="news", data={"headline": "test"}, timestamp=1.0)
        mgr.publish("news", obj)

        assert len(received) == 1
        assert received[0] == obj

    def test_publish_stores_object(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        obj = _dummy_object(data={"x": 1}, timestamp=2.0)
        mgr.publish("updates", obj)
        assert mem_store.has(obj.id)

    def test_unsubscribe(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        cb = lambda tid, obj: received.append(obj)
        mgr.subscribe("news", cb)
        mgr.unsubscribe("news", cb)

        obj = _dummy_object(data={"x": 1}, timestamp=3.0)
        mgr.publish("news", obj)
        assert received == []

    def test_duplicate_suppression(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        mgr.subscribe("ch", lambda tid, obj: received.append(obj))

        obj = _dummy_object(data={"y": 1}, timestamp=4.0)
        mgr.publish("ch", obj)
        mgr.publish("ch", obj)  # second publish of same object

        # callback fired once; second is a duplicate
        assert len(received) == 1

    def test_handle_raw_valid_message(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        mgr.subscribe("x", lambda tid, obj: received.append(obj))

        obj = _dummy_object(data={"z": 1}, timestamp=5.0)
        tid = topic_id("x")
        wire = {
            "murnet_pubsub": True,
            "action": "publish",
            "topic": tid,
            "object": obj.to_dict(),
            "ttl": 3,
            "seen_by": [],
        }
        mgr.handle_raw(json.dumps(wire).encode(), "127.0.0.1", 8888)
        assert len(received) == 1
        assert received[0] == obj

    def test_handle_raw_non_pubsub_ignored(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        mgr.subscribe("x", lambda tid, obj: received.append(obj))

        mgr.handle_raw(json.dumps({"type": "message"}).encode(), "127.0.0.1", 8888)
        assert received == []

    def test_handle_raw_invalid_json_ignored(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        mgr.handle_raw(b"not json", "127.0.0.1", 8888)  # must not raise

    def test_handle_raw_tampered_object_dropped(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        mgr.subscribe("y", lambda tid, obj: received.append(obj))

        obj = _dummy_object(data={"a": 1}, timestamp=6.0)
        d = obj.to_dict()
        d["data"]["a"] = 99   # tamper with content
        tid = topic_id("y")
        wire = {
            "murnet_pubsub": True,
            "action": "publish",
            "topic": tid,
            "object": d,
            "ttl": 3,
            "seen_by": [],
        }
        mgr.handle_raw(json.dumps(wire).encode(), "127.0.0.1", 8888)
        assert received == []

    def test_stats_keys(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        s = mgr.get_stats()
        for key in ("published", "received", "forwarded", "duplicates", "subscriptions", "topics"):
            assert key in s

    def test_subscription_topics(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        mgr.subscribe("room:a", lambda *_: None)
        mgr.subscribe("room:b", lambda *_: None)
        topics = mgr.subscription_topics()
        assert topic_id("room:a") in topics
        assert topic_id("room:b") in topics


# ===========================================================================
# PubSubManager — async path
# ===========================================================================


class TestPubSubAsync:
    def test_async_publish(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        mgr.subscribe("async_test", lambda tid, obj: received.append(obj))

        obj = _dummy_object(data={"msg": "async"}, timestamp=7.0)

        asyncio.run(mgr.async_publish("async_test", obj))
        assert len(received) == 1

    def test_async_handle_raw(self, mem_store):
        mgr = PubSubManager(mem_store, "1NodeA", transport=None)
        received = []
        mgr.subscribe("async_ch", lambda tid, obj: received.append(obj))

        obj = _dummy_object(data={"msg": "raw"}, timestamp=8.0)
        tid = topic_id("async_ch")
        wire = {
            "murnet_pubsub": True,
            "action": "publish",
            "topic": tid,
            "object": obj.to_dict(),
            "ttl": 2,
            "seen_by": [],
        }

        asyncio.run(mgr.async_handle_raw(json.dumps(wire).encode(), "127.0.0.1", 8888))
        assert len(received) == 1
