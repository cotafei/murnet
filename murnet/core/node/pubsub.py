"""
MurNet v6.2 — Publish / Subscribe Layer

Topics are addressed by their Blake2b-128 hash (32-char hex), so any string
name maps to a compact, collision-resistant key.

Architecture
------------
* ``PubSubManager`` sits on top of ``AsyncTransport`` (or any transport that
  supports ``register_handler()`` / ``send_raw()``).
* When a node publishes an object it:
  1. Stores it locally in ``ObjectStore``.
  2. Broadcasts a ``PUBSUB_PUBLISH`` message to all connected peers.
* When a peer receives a ``PUBSUB_PUBLISH`` message it:
  1. Checks whether the object ID was seen already (dedup set).
  2. Stores the object locally.
  3. Fires all local ``subscribe()`` callbacks for that topic.
  4. Forwards the message to *its* peers (gossip — one hop by default, TTL
     field controls further propagation).
* Subscriptions are purely local; they are not advertised to the network.
  Interested nodes will receive objects for a topic only when they are
  reachable in the gossip path.

Wire message (JSON, sent as the DATA payload over AsyncTransport)::

    {
        "murnet_pubsub": true,
        "action":        "publish",
        "topic":         "<32-char hex topic hash>",
        "object":        { <MurObject.to_dict()> },
        "ttl":           3,
        "seen_by":       ["<sender_address>"]
    }

Thread / asyncio safety
-----------------------
All public methods are safe to call from sync code.  The ``async_*`` variants
are provided for use inside async tasks.  Callbacks are invoked from the
event loop thread when the underlying transport is async.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from hashlib import blake2b
from typing import Any, Callable, Dict, List, Optional, Set

from murnet.core.data.objects import MurObject, ObjectStore

logger = logging.getLogger(__name__)

# Maximum number of recently-seen object IDs kept for dedup
_SEEN_DEDUP_SIZE = 4096
# Default gossip TTL (hops)
_DEFAULT_TTL = 3
# Maximum subscribers per topic
_MAX_SUBS_PER_TOPIC = 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def topic_id(name: str) -> str:
    """
    Map a human-readable topic name to a 32-char hex Blake2b-128 topic hash.

    Examples
    --------
    >>> topic_id("room:general")
    'f3a8...'
    """
    return blake2b(name.encode(), digest_size=16).hexdigest()


# ---------------------------------------------------------------------------
# PubSubManager
# ---------------------------------------------------------------------------


class PubSubManager:
    """
    Gossip-based publish/subscribe manager.

    Parameters
    ----------
    object_store : ObjectStore
        Where received and published objects are persisted.
    node_address : str
        Base58 address of the local node (used to tag ``seen_by`` lists and
        prevent re-broadcasting to the originating peer).
    transport : object | None
        The transport layer.  Must expose either:
          * ``async_broadcast(payload_bytes)`` — for async transport, OR
          * ``broadcast(payload_bytes)``       — for sync transport.
        If *None* the manager operates in pure local mode (useful for tests).
    """

    def __init__(
        self,
        object_store: ObjectStore,
        node_address: str,
        transport=None,
    ) -> None:
        self._store = object_store
        self._address = node_address
        self._transport = transport

        # topic_hash -> list of callbacks(topic_hash, MurObject)
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)

        # Recently forwarded object IDs (dedup ring buffer)
        self._seen: deque = deque(maxlen=_SEEN_DEDUP_SIZE)
        self._seen_set: Set[str] = set()

        # Stats
        self._stats: Dict[str, int] = {
            "published":  0,
            "received":   0,
            "forwarded":  0,
            "duplicates": 0,
        }

    # ------------------------------------------------------------------
    # Subscribe / unsubscribe
    # ------------------------------------------------------------------

    def subscribe(self, topic: str, callback: Callable[[str, MurObject], Any]) -> None:
        """
        Register *callback* to be called whenever an object arrives on *topic*.

        Parameters
        ----------
        topic    : str — human-readable topic name or pre-hashed topic_id
        callback : callable(topic_id: str, obj: MurObject) -> Any
        """
        tid = topic_id(topic) if len(topic) != 32 else topic
        subs = self._subscribers[tid]
        if len(subs) >= _MAX_SUBS_PER_TOPIC:
            raise RuntimeError(f"Too many subscribers for topic {topic!r}")
        if callback not in subs:
            subs.append(callback)
        logger.debug("Subscribed to topic %s (%s)", topic, tid[:8])

    def unsubscribe(self, topic: str, callback: Callable) -> bool:
        """
        Remove *callback* from *topic*.  Returns True if it was present.
        """
        tid = topic_id(topic) if len(topic) != 32 else topic
        subs = self._subscribers.get(tid, [])
        try:
            subs.remove(callback)
            return True
        except ValueError:
            return False

    def subscription_topics(self) -> List[str]:
        """Return the list of topic IDs that have at least one subscriber."""
        return [tid for tid, subs in self._subscribers.items() if subs]

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(self, topic: str, obj: MurObject, ttl: int = _DEFAULT_TTL) -> None:
        """
        Publish *obj* to *topic* (sync wrapper).

        Stores the object locally, fires local callbacks, then broadcasts to
        all connected peers.  A second call with the same object ID is a no-op
        (dedup).
        """
        if self._is_seen(obj.id):
            return
        tid = topic_id(topic) if len(topic) != 32 else topic
        self._handle_new_object(tid, obj)
        self._broadcast_sync(tid, obj, ttl)

    async def async_publish(
        self, topic: str, obj: MurObject, ttl: int = _DEFAULT_TTL
    ) -> None:
        """Async variant of :meth:`publish`."""
        if self._is_seen(obj.id):
            return
        tid = topic_id(topic) if len(topic) != 32 else topic
        self._handle_new_object(tid, obj)
        await self._broadcast_async(tid, obj, ttl)

    # ------------------------------------------------------------------
    # Incoming message handler (registered with transport)
    # ------------------------------------------------------------------

    def handle_raw(self, payload: bytes, sender_ip: str, sender_port: int) -> None:
        """
        Called by the transport layer when a DATA packet arrives.

        Sync handler — safe to call from any thread; forwards objects via
        sync transport broadcast if needed.
        """
        try:
            msg = json.loads(payload.decode())
        except Exception:
            return
        if not msg.get("murnet_pubsub"):
            return

        action = msg.get("action")
        if action == "publish":
            self._on_publish_message(msg, sync_forward=True)

    async def async_handle_raw(
        self, payload: bytes, sender_ip: str, sender_port: int
    ) -> None:
        """Async variant of :meth:`handle_raw`."""
        try:
            msg = json.loads(payload.decode())
        except Exception:
            return
        if not msg.get("murnet_pubsub"):
            return

        action = msg.get("action")
        if action == "publish":
            await self._on_publish_message_async(msg)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "subscriptions": sum(len(v) for v in self._subscribers.values()),
            "topics":        len([t for t, s in self._subscribers.items() if s]),
            "seen_cache":    len(self._seen_set),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_new_object(self, topic_id_hex: str, obj: MurObject) -> None:
        """Store locally and fire callbacks."""
        try:
            self._store.put(obj)
        except ValueError as exc:
            logger.warning("PubSub: rejected object %s: %s", obj.id[:8], exc)
            return

        self._mark_seen(obj.id)
        self._fire_callbacks(topic_id_hex, obj)
        self._stats["published"] += 1

    def _on_publish_message(self, msg: dict, sync_forward: bool = False) -> None:
        """Process a received publish gossip message (sync path)."""
        try:
            obj = MurObject.from_dict(msg["object"])
            tid = str(msg["topic"])
            ttl = int(msg.get("ttl", _DEFAULT_TTL))
            seen_by: List[str] = list(msg.get("seen_by", []))
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("PubSub: malformed publish message: %s", exc)
            return

        if self._is_seen(obj.id):
            self._stats["duplicates"] += 1
            return

        if not obj.verify_id():
            logger.debug("PubSub: dropping object %s — ID mismatch", obj.id[:8])
            return

        try:
            self._store.put(obj)
        except ValueError:
            pass

        self._mark_seen(obj.id)
        self._fire_callbacks(tid, obj)
        self._stats["received"] += 1

        # Gossip forward
        if ttl > 1:
            seen_by_updated = list(set(seen_by) | {self._address})
            self._gossip_forward_sync(tid, obj, ttl - 1, seen_by_updated)

    async def _on_publish_message_async(self, msg: dict) -> None:
        """Process a received publish gossip message (async path)."""
        try:
            obj = MurObject.from_dict(msg["object"])
            tid = str(msg["topic"])
            ttl = int(msg.get("ttl", _DEFAULT_TTL))
            seen_by: List[str] = list(msg.get("seen_by", []))
        except (KeyError, ValueError, TypeError) as exc:
            logger.debug("PubSub: malformed publish message: %s", exc)
            return

        if self._is_seen(obj.id):
            self._stats["duplicates"] += 1
            return

        if not obj.verify_id():
            logger.debug("PubSub: dropping object %s — ID mismatch", obj.id[:8])
            return

        try:
            self._store.put(obj)
        except ValueError:
            pass

        self._mark_seen(obj.id)
        self._fire_callbacks(tid, obj)
        self._stats["received"] += 1

        if ttl > 1:
            seen_by_updated = list(set(seen_by) | {self._address})
            await self._gossip_forward_async(tid, obj, ttl - 1, seen_by_updated)

    def _fire_callbacks(self, topic_id_hex: str, obj: MurObject) -> None:
        for cb in list(self._subscribers.get(topic_id_hex, [])):
            try:
                cb(topic_id_hex, obj)
            except Exception as exc:
                logger.exception("PubSub: subscriber callback raised: %s", exc)

    # ------------------------------------------------------------------
    # Gossip forwarding
    # ------------------------------------------------------------------

    def _build_wire(
        self, tid: str, obj: MurObject, ttl: int, seen_by: List[str]
    ) -> bytes:
        msg = {
            "murnet_pubsub": True,
            "action":        "publish",
            "topic":         tid,
            "object":        obj.to_dict(),
            "ttl":           ttl,
            "seen_by":       seen_by,
        }
        return json.dumps(msg).encode()

    def _broadcast_sync(self, tid: str, obj: MurObject, ttl: int) -> None:
        if self._transport is None:
            return
        payload = self._build_wire(tid, obj, ttl, [self._address])
        try:
            if hasattr(self._transport, "broadcast"):
                self._transport.broadcast(payload)
                self._stats["forwarded"] += 1
        except Exception as exc:
            logger.warning("PubSub: broadcast error: %s", exc)

    async def _broadcast_async(self, tid: str, obj: MurObject, ttl: int) -> None:
        if self._transport is None:
            return
        payload = self._build_wire(tid, obj, ttl, [self._address])
        try:
            if hasattr(self._transport, "async_broadcast"):
                await self._transport.async_broadcast(payload)
                self._stats["forwarded"] += 1
            elif hasattr(self._transport, "broadcast"):
                self._transport.broadcast(payload)
                self._stats["forwarded"] += 1
        except Exception as exc:
            logger.warning("PubSub: async broadcast error: %s", exc)

    def _gossip_forward_sync(
        self, tid: str, obj: MurObject, ttl: int, seen_by: List[str]
    ) -> None:
        if self._transport is None:
            return
        payload = self._build_wire(tid, obj, ttl, seen_by)
        try:
            if hasattr(self._transport, "broadcast"):
                self._transport.broadcast(payload)
                self._stats["forwarded"] += 1
        except Exception as exc:
            logger.warning("PubSub: forward error: %s", exc)

    async def _gossip_forward_async(
        self, tid: str, obj: MurObject, ttl: int, seen_by: List[str]
    ) -> None:
        if self._transport is None:
            return
        payload = self._build_wire(tid, obj, ttl, seen_by)
        try:
            if hasattr(self._transport, "async_broadcast"):
                await self._transport.async_broadcast(payload)
                self._stats["forwarded"] += 1
            elif hasattr(self._transport, "broadcast"):
                self._transport.broadcast(payload)
                self._stats["forwarded"] += 1
        except Exception as exc:
            logger.warning("PubSub: async forward error: %s", exc)

    # ------------------------------------------------------------------
    # Dedup helpers
    # ------------------------------------------------------------------

    def _is_seen(self, obj_id: str) -> bool:
        return obj_id in self._seen_set

    def _mark_seen(self, obj_id: str) -> None:
        if obj_id not in self._seen_set:
            if len(self._seen) >= _SEEN_DEDUP_SIZE:
                evicted = self._seen[0]   # deque auto-evicts, just sync set
                self._seen_set.discard(evicted)
            self._seen.append(obj_id)
            self._seen_set.add(obj_id)
