"""
Unit tests for core/node/pubsub.py — PubSubManager.
"""
import asyncio
import json
import os
import time
import pytest

from core.node.pubsub import PubSubManager, topic_id, _DEFAULT_TTL
from core.data.objects import MurObject, ObjectStore


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _store(tmp_path) -> ObjectStore:
    return ObjectStore(str(tmp_path))


def _obj(owner: str = "node-1", text: str = "hello") -> MurObject:
    return MurObject.create(
        obj_type="msg",
        owner=owner,
        data={"text": text},
    )


def _psm(tmp_path, transport=None) -> PubSubManager:
    return PubSubManager(_store(tmp_path), "node-1", transport)


class FakeTransport:
    """Captures broadcast payloads without actually sending."""
    def __init__(self):
        self.sent: list[bytes] = []

    def broadcast(self, payload: bytes) -> None:
        self.sent.append(payload)

    async def async_broadcast(self, payload: bytes) -> None:
        self.sent.append(payload)


# ─────────────────────────────────────────────────────────────────────────────
# topic_id
# ─────────────────────────────────────────────────────────────────────────────

class TestTopicId:

    def test_returns_32_char_hex(self):
        tid = topic_id("room:general")
        assert len(tid) == 32
        assert all(c in "0123456789abcdef" for c in tid)

    def test_deterministic(self):
        assert topic_id("x") == topic_id("x")

    def test_different_names_different_ids(self):
        assert topic_id("a") != topic_id("b")

    def test_already_hashed_passthrough(self):
        # If a 32-char hex is passed as topic, subscribe/publish treat it as-is
        tid = topic_id("something")
        psm = PubSubManager(ObjectStore.__new__(ObjectStore), "node", None)
        psm._store = type("S", (), {"put": lambda *a, **k: None})()
        cb = lambda t, o: None
        psm.subscribe(tid, cb)       # should NOT double-hash
        assert tid in psm._subscribers


# ─────────────────────────────────────────────────────────────────────────────
# Subscribe / unsubscribe
# ─────────────────────────────────────────────────────────────────────────────

class TestSubscribe:

    def test_subscribe_registers_callback(self, tmp_path):
        psm = _psm(tmp_path)
        cb = lambda t, o: None
        psm.subscribe("chat", cb)
        assert topic_id("chat") in psm._subscribers
        assert cb in psm._subscribers[topic_id("chat")]

    def test_subscribe_idempotent(self, tmp_path):
        psm = _psm(tmp_path)
        cb = lambda t, o: None
        psm.subscribe("chat", cb)
        psm.subscribe("chat", cb)
        assert psm._subscribers[topic_id("chat")].count(cb) == 1

    def test_unsubscribe_removes_callback(self, tmp_path):
        psm = _psm(tmp_path)
        cb = lambda t, o: None
        psm.subscribe("chat", cb)
        result = psm.unsubscribe("chat", cb)
        assert result is True
        assert cb not in psm._subscribers[topic_id("chat")]

    def test_unsubscribe_nonexistent_returns_false(self, tmp_path):
        psm = _psm(tmp_path)
        result = psm.unsubscribe("chat", lambda t, o: None)
        assert result is False

    def test_subscription_topics_lists_active(self, tmp_path):
        psm = _psm(tmp_path)
        psm.subscribe("room-a", lambda t, o: None)
        psm.subscribe("room-b", lambda t, o: None)
        topics = psm.subscription_topics()
        assert topic_id("room-a") in topics
        assert topic_id("room-b") in topics

    def test_subscription_topics_excludes_empty(self, tmp_path):
        psm = _psm(tmp_path)
        cb = lambda t, o: None
        psm.subscribe("room-a", cb)
        psm.unsubscribe("room-a", cb)
        assert topic_id("room-a") not in psm.subscription_topics()

    def test_too_many_subscribers_raises(self, tmp_path):
        from core.node.pubsub import _MAX_SUBS_PER_TOPIC
        psm = _psm(tmp_path)
        for i in range(_MAX_SUBS_PER_TOPIC):
            psm.subscribe("flood", lambda t, o, i=i: i)
        with pytest.raises(RuntimeError, match="Too many subscribers"):
            psm.subscribe("flood", lambda t, o: None)


# ─────────────────────────────────────────────────────────────────────────────
# Publish (local mode — no transport)
# ─────────────────────────────────────────────────────────────────────────────

class TestPublishLocal:

    def test_callback_fires_on_publish(self, tmp_path):
        psm = _psm(tmp_path)
        received = []
        psm.subscribe("news", lambda t, o: received.append(o))

        obj = _obj()
        psm.publish("news", obj)
        assert len(received) == 1
        assert received[0].id == obj.id

    def test_publish_stores_object(self, tmp_path):
        psm = _psm(tmp_path)
        obj = _obj()
        psm.publish("news", obj)
        assert psm._store.get(obj.id) is not None

    def test_duplicate_publish_is_noop(self, tmp_path):
        psm = _psm(tmp_path)
        calls = []
        psm.subscribe("news", lambda t, o: calls.append(o))

        obj = _obj()
        psm.publish("news", obj)
        psm.publish("news", obj)   # second call — same object
        assert len(calls) == 1

    def test_stats_published_increments(self, tmp_path):
        psm = _psm(tmp_path)
        psm.publish("news", _obj(text="a"))
        psm.publish("news", _obj(text="b"))
        assert psm.get_stats()["published"] == 2

    def test_multiple_callbacks_same_topic(self, tmp_path):
        psm = _psm(tmp_path)
        a, b = [], []
        psm.subscribe("t", lambda t, o: a.append(o))
        psm.subscribe("t", lambda t, o: b.append(o))
        psm.publish("t", _obj())
        assert len(a) == len(b) == 1

    def test_callback_exception_does_not_crash_publish(self, tmp_path):
        psm = _psm(tmp_path)
        psm.subscribe("t", lambda t, o: 1 / 0)   # always raises
        psm.publish("t", _obj())                  # should not propagate

    def test_publish_different_topics_independent(self, tmp_path):
        psm = _psm(tmp_path)
        news, alerts = [], []
        psm.subscribe("news",   lambda t, o: news.append(o))
        psm.subscribe("alerts", lambda t, o: alerts.append(o))
        psm.publish("news", _obj(text="n"))
        assert len(news) == 1 and len(alerts) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Publish with transport (broadcast)
# ─────────────────────────────────────────────────────────────────────────────

class TestPublishWithTransport:

    def test_broadcast_called_on_publish(self, tmp_path):
        transport = FakeTransport()
        psm = _psm(tmp_path, transport)
        psm.publish("news", _obj())
        assert len(transport.sent) == 1

    def test_broadcast_payload_is_valid_json(self, tmp_path):
        transport = FakeTransport()
        psm = _psm(tmp_path, transport)
        psm.publish("news", _obj())
        msg = json.loads(transport.sent[0])
        assert msg["murnet_pubsub"] is True
        assert msg["action"] == "publish"
        assert "topic" in msg and "object" in msg

    def test_broadcast_contains_ttl(self, tmp_path):
        transport = FakeTransport()
        psm = _psm(tmp_path, transport)
        psm.publish("news", _obj(), ttl=5)
        msg = json.loads(transport.sent[0])
        assert msg["ttl"] == 5


# ─────────────────────────────────────────────────────────────────────────────
# Incoming messages (handle_raw)
# ─────────────────────────────────────────────────────────────────────────────

class TestHandleRaw:

    def _wire(self, psm: PubSubManager, obj: MurObject, ttl: int = 2) -> bytes:
        tid = topic_id("news")
        msg = {
            "murnet_pubsub": True,
            "action":        "publish",
            "topic":         tid,
            "object":        obj.to_dict(),
            "ttl":           ttl,
            "seen_by":       ["other-node"],
        }
        return json.dumps(msg).encode()

    def test_handle_raw_fires_callback(self, tmp_path):
        psm = _psm(tmp_path)
        received = []
        psm.subscribe("news", lambda t, o: received.append(o))

        obj = _obj()
        psm.handle_raw(self._wire(psm, obj), "1.2.3.4", 9000)
        assert len(received) == 1
        assert received[0].id == obj.id

    def test_handle_raw_duplicate_ignored(self, tmp_path):
        psm = _psm(tmp_path)
        calls = []
        psm.subscribe("news", lambda t, o: calls.append(o))

        obj = _obj()
        wire = self._wire(psm, obj)
        psm.handle_raw(wire, "1.2.3.4", 9000)
        psm.handle_raw(wire, "1.2.3.4", 9000)
        assert len(calls) == 1
        assert psm.get_stats()["duplicates"] == 1

    def test_handle_raw_ignores_non_pubsub(self, tmp_path):
        psm = _psm(tmp_path)
        calls = []
        psm.subscribe("news", lambda t, o: calls.append(o))
        psm.handle_raw(json.dumps({"type": "other"}).encode(), "x", 0)
        assert len(calls) == 0

    def test_handle_raw_ignores_bad_json(self, tmp_path):
        psm = _psm(tmp_path)
        psm.handle_raw(b"not json {{", "x", 0)  # should not raise

    def test_handle_raw_forwards_when_ttl_gt_1(self, tmp_path):
        transport = FakeTransport()
        psm = _psm(tmp_path, transport)
        obj = _obj()
        psm.handle_raw(self._wire(psm, obj, ttl=3), "1.2.3.4", 9000)
        assert len(transport.sent) == 1
        fwd = json.loads(transport.sent[0])
        assert fwd["ttl"] == 2   # decremented

    def test_handle_raw_no_forward_when_ttl_1(self, tmp_path):
        transport = FakeTransport()
        psm = _psm(tmp_path, transport)
        obj = _obj()
        psm.handle_raw(self._wire(psm, obj, ttl=1), "1.2.3.4", 9000)
        assert len(transport.sent) == 0

    def test_stats_received_increments(self, tmp_path):
        psm = _psm(tmp_path)
        psm.handle_raw(self._wire(psm, _obj(text="x")), "x", 0)
        assert psm.get_stats()["received"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Async publish
# ─────────────────────────────────────────────────────────────────────────────

class TestAsyncPublish:

    @pytest.mark.asyncio
    async def test_async_publish_fires_callback(self, tmp_path):
        transport = FakeTransport()
        psm = _psm(tmp_path, transport)
        received = []
        psm.subscribe("news", lambda t, o: received.append(o))

        obj = _obj()
        await psm.async_publish("news", obj)
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_async_publish_broadcasts(self, tmp_path):
        transport = FakeTransport()
        psm = _psm(tmp_path, transport)
        await psm.async_publish("news", _obj())
        assert len(transport.sent) == 1

    @pytest.mark.asyncio
    async def test_async_handle_raw_fires_callback(self, tmp_path):
        psm = _psm(tmp_path)
        received = []
        psm.subscribe("news", lambda t, o: received.append(o))

        obj  = _obj()
        tid  = topic_id("news")
        wire = json.dumps({
            "murnet_pubsub": True,
            "action": "publish",
            "topic":  tid,
            "object": obj.to_dict(),
            "ttl":    1,
            "seen_by": [],
        }).encode()
        await psm.async_handle_raw(wire, "1.2.3.4", 9000)
        assert len(received) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────────────────────────────────────

class TestStats:

    def test_stats_keys_present(self, tmp_path):
        psm = _psm(tmp_path)
        s = psm.get_stats()
        for key in ("published", "received", "forwarded", "duplicates",
                    "subscriptions", "topics", "seen_cache"):
            assert key in s

    def test_stats_subscriptions_count(self, tmp_path):
        psm = _psm(tmp_path)
        psm.subscribe("a", lambda t, o: None)
        psm.subscribe("a", lambda t, o: None)
        psm.subscribe("b", lambda t, o: None)
        assert psm.get_stats()["subscriptions"] == 3
        assert psm.get_stats()["topics"] == 2
