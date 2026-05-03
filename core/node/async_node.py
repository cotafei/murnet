"""
MURNET ASYNC NODE v6.0
Full asyncio replacement for SecureMurnetNode.

Keeps the same public interface as SecureMurnetNode so existing code that
calls .start() / .stop() / .send_message() / .get_status() still works,
but all I/O is driven by asyncio tasks instead of threads.

Usage (standalone):
    import asyncio
    from core.async_node import AsyncMurnetNode

    async def main():
        node = AsyncMurnetNode(port=8888)
        await node.start()
        await node.send_message("1RecipientAddr...", "hello")
        await asyncio.sleep(60)
        await node.stop()

    asyncio.run(main())
"""

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from core.net.async_transport import AsyncTransport
from core.identity.crypto import E2EEncryption, Identity, blake2b_hash
from core.net.murnaked import MurnakedNode
from core.data.objects import ObjectStore
from core.node.pubsub import PubSubManager
from core.net.routing import RoutingTable
from core.data.storage import Storage
from core.config import get_config

logger = logging.getLogger(__name__)

_HEARTBEAT_INTERVAL = 30.0   # seconds
_RETRY_DELAY_BASE   = 2.0    # seconds (doubles each retry)
_MAX_RETRY_DELAY    = 60.0
_MAX_RETRIES        = 5
_OUTBOX_MAXSIZE     = 100_000


class AsyncMurnetNode:
    """
    Async P2P node for Murnet v6.0.

    All blocking I/O (storage, DHT) runs in the default executor so the
    event loop is never blocked.
    """

    def __init__(self, data_dir: str = "./data", port: int = 8888, password: Optional[str] = None):
        self.data_dir = data_dir
        self.port = port
        self.running = False
        self.config = get_config()

        # Storage (sync SQLite — offloaded via run_in_executor)
        self.storage = Storage(data_dir, config=self.config.storage)

        # Identity (password-protected if password supplied)
        self._init_identity(password=password)

        # Async transport
        self.transport = AsyncTransport(port=port)
        self.transport.on_message           = self._on_message
        self.transport.on_peer_connected    = self._on_peer_connected
        self.transport.on_peer_disconnected = self._on_peer_disconnected

        # Routing & DHT (sync-safe, protected internally by locks)
        self.routing = RoutingTable(self.address, self.identity)
        self.murnaked = MurnakedNode(
            node_address=f"127.0.0.1:{port}",
            node_id=hashlib.sha256(self.address.encode()).digest(),
            identity=self.identity,
            data_dir=data_dir,
            transport=None,        # DHT uses its own sync transport for now
            node_instance=self,
        )

        # E2E encryption
        self.e2e = E2EEncryption(self.identity)

        # v6.2 Object system + Pub/Sub
        self.object_store = ObjectStore(data_dir)
        self.pubsub = PubSubManager(
            object_store=self.object_store,
            node_address=self.address,
            transport=self.transport,
        )

        # Outbox: (to_addr, payload_bytes, retries_left, next_attempt)
        self._outbox: asyncio.Queue = asyncio.Queue(maxsize=_OUTBOX_MAXSIZE)

        # Stats
        self.stats: Dict[str, Any] = {
            "messages_sent": 0,
            "messages_received": 0,
            "messages_failed": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "start_time": time.time(),
        }

        # Background task handles
        self._tasks: List[asyncio.Task] = []

        # External message callback
        self.on_message_received: Optional[Callable[[str, str, str], Any]] = None

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def _init_identity(self, password: Optional[str] = None):
        if password is not None:
            self._init_identity_encrypted(password)
        else:
            self._init_identity_plain()

    def _init_identity_encrypted(self, password: str) -> None:
        """Load or create identity protected by a user password (Argon2id + AES-GCM)."""
        from core.identity.keystore import EncryptedKeystore, WrongPasswordError, WeakPasswordError
        ks = EncryptedKeystore(self.data_dir)
        if ks.exists():
            # Raises WrongPasswordError on bad password — intentionally propagated
            key_bytes = ks.load(password)
            self.identity = Identity.from_bytes(key_bytes)
            logger.info("Identity unlocked: %s…", self.identity.address[:16])
        else:
            self.identity = Identity()
            ks.create(self.identity.to_bytes(), password)
            logger.info("New identity created (encrypted): %s…", self.identity.address[:16])
        self.address = self.identity.address
        self.public_key = self.identity.get_public_bytes()

    def _init_identity_plain(self) -> None:
        """Legacy: load/save identity from SQLite without password protection."""
        key_bytes = self.storage.load_identity()
        if key_bytes:
            self.identity = Identity.from_bytes(key_bytes)
            logger.info("Loaded identity: %s…", self.identity.address[:16])
        else:
            self.identity = Identity()
            self.storage.save_identity(self.identity.to_bytes())
            logger.info("Generated new identity: %s…", self.identity.address[:16])
        self.address = self.identity.address
        self.public_key = self.identity.get_public_bytes()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self):
        """Start transport, DHT and background tasks."""
        if self.running:
            return
        self.running = True
        logger.info("AsyncMurnetNode starting on port %d…", self.port)

        await self.transport.start()
        self.murnaked.start()

        self._tasks = [
            asyncio.ensure_future(self._outbox_loop()),
            asyncio.ensure_future(self._heartbeat_loop()),
            asyncio.ensure_future(self._routing_sync_loop()),
        ]
        logger.info("Node ready. Address: %s", self.address)

    async def stop(self):
        """Gracefully stop all tasks and transport."""
        self.running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.transport.stop()
        try:
            self.murnaked.stop()
        except Exception:
            pass
        logger.info("AsyncMurnetNode stopped.")

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def send_message(
        self,
        to_addr: str,
        text: str,
        encrypt: bool = True,
        ttl: int = 86400,
    ) -> Optional[str]:
        """
        Queue an outgoing message.  Returns message_id or None on error.
        """
        msg_id = str(uuid.uuid4())

        try:
            payload = self._build_payload(msg_id, to_addr, text, encrypt, ttl)
        except Exception as exc:
            logger.error("Failed to build payload: %s", exc)
            return None

        # Persist before sending (so we can retry after crash)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self.storage.save_message(
                msg_id=msg_id,
                from_addr=self.address,
                to_addr=to_addr,
                text=text[:256],
                timestamp=time.time(),
                delivered=False,
            ),
        )

        await self._outbox.put({
            "msg_id": msg_id,
            "to_addr": to_addr,
            "payload": payload,
            "retries_left": _MAX_RETRIES,
            "next_attempt": 0.0,
        })
        return msg_id

    def _build_payload(
        self, msg_id: str, to_addr: str, text: str, encrypt: bool, ttl: int
    ) -> bytes:
        envelope = {
            "id": msg_id,
            "from": self.address,
            "to": to_addr,
            "text": text,
            "timestamp": time.time(),
            "ttl": ttl,
        }
        if encrypt:
            session_key = self.e2e.get_session_key(to_addr)
            if session_key:
                encrypted = self.e2e.encrypt(json.dumps(envelope).encode(), session_key)
                return json.dumps({"type": "encrypted", "data": encrypted.hex()}).encode()
        return json.dumps({"type": "plain", **envelope}).encode()

    # ------------------------------------------------------------------
    # Peer connectivity
    # ------------------------------------------------------------------

    async def connect_to_peer(self, ip: str, port: int, address: str = "") -> bool:
        """Initiate handshake with a remote peer."""
        return await self.transport.connect(ip, port, address)

    def get_peers(self) -> list:
        return self.transport.get_peers()

    # ------------------------------------------------------------------
    # Name Service
    # ------------------------------------------------------------------

    def register_name(self, name: str) -> bool:
        if not name or len(name) > 64:
            return False
        signature = self.identity.sign({"name": name, "address": self.address})
        return self.murnaked.register_name(name, self.address, signature)

    def lookup_name(self, name: str) -> Optional[str]:
        if not name or len(name) > 64:
            return None
        result = self.murnaked.get_name(name)
        if result and isinstance(result, dict):
            return result.get("address")
        return None

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        uptime = time.time() - self.stats["start_time"]
        peers = self.get_peers()
        active_peers = [p for p in peers if p.get("is_active")]
        return {
            "address": self.address,
            "version": "v6.0-async",
            "running": self.running,
            "uptime": round(uptime, 1),
            "peers_count": len(active_peers),
            "neighbors": len(self.routing.local_links),
            "messages_sent": self.stats["messages_sent"],
            "messages_received": self.stats["messages_received"],
            "messages_failed": self.stats["messages_failed"],
            "outbox_qsize": self._outbox.qsize(),
        }

    # ------------------------------------------------------------------
    # Transport callbacks
    # ------------------------------------------------------------------

    async def _on_message(self, data: bytes, sender_addr: str, addr):
        self.stats["messages_received"] += 1
        self.stats["bytes_received"] += len(data)
        try:
            envelope = json.loads(data.decode())
        except Exception:
            logger.debug("Unparseable message from %s", sender_addr)
            return

        # v6.2: route pub/sub gossip messages to PubSubManager
        if envelope.get("murnet_pubsub"):
            ip, port = (addr[0], addr[1]) if isinstance(addr, (tuple, list)) else (str(addr), 0)
            await self.pubsub.async_handle_raw(data, ip, port)
            return

        msg_type = envelope.get("type")
        if msg_type == "encrypted":
            session_key = self.e2e.get_session_key(sender_addr)
            if session_key:
                try:
                    raw = self.e2e.decrypt(
                        bytes.fromhex(envelope["data"]), session_key
                    )
                    envelope = json.loads(raw.decode())
                except Exception as exc:
                    logger.warning("Decryption failed from %s: %s", sender_addr, exc)
                    return

        text = envelope.get("text", "")
        msg_from = envelope.get("from", sender_addr)
        msg_to = envelope.get("to", self.address)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self.storage.save_message(
                msg_id=envelope.get("id", str(uuid.uuid4())),
                from_addr=msg_from,
                to_addr=msg_to,
                text=text[:256],
                timestamp=envelope.get("timestamp", time.time()),
                delivered=True,
            ),
        )

        if self.on_message_received:
            await asyncio.coroutine(self.on_message_received)(msg_from, msg_to, text) \
                if asyncio.iscoroutinefunction(self.on_message_received) \
                else asyncio.get_event_loop().run_in_executor(
                    None, self.on_message_received, msg_from, msg_to, text
                )

    async def _on_peer_connected(self, address: str, addr):
        logger.info("Peer connected: %s @ %s:%s", address[:16], *addr)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.routing.add_neighbor, address)

    async def _on_peer_disconnected(self, address: str, addr):
        logger.info("Peer disconnected: %s", address[:16])
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.routing.remove_link, address)

    # ------------------------------------------------------------------
    # Background loops
    # ------------------------------------------------------------------

    async def _outbox_loop(self):
        """Drain the outbox with exponential backoff retries."""
        while self.running:
            try:
                item = await asyncio.wait_for(self._outbox.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            now = time.time()
            if item["next_attempt"] > now:
                # Put back and yield
                await self._outbox.put(item)
                await asyncio.sleep(0.1)
                continue

            success = await self._deliver(item)
            if success:
                self.stats["messages_sent"] += 1
            elif item["retries_left"] > 0:
                item["retries_left"] -= 1
                attempts_done = _MAX_RETRIES - item["retries_left"]
                delay = min(_RETRY_DELAY_BASE * (2 ** attempts_done), _MAX_RETRY_DELAY)
                item["next_attempt"] = time.time() + delay
                await self._outbox.put(item)
            else:
                self.stats["messages_failed"] += 1
                logger.warning("Message %s permanently failed (no retries left).", item["msg_id"])

    async def _deliver(self, item: dict) -> bool:
        """Find route and send one message item."""
        to_addr = item["to_addr"]
        payload = item["payload"]

        # Try direct peer first
        for peer in self.transport.get_peers():
            if peer["address"] == to_addr:
                ok = await self.transport.send_message(payload, (peer["ip"], peer["port"]))
                self.stats["bytes_sent"] += len(payload)
                return ok

        # Try routing table
        loop = asyncio.get_event_loop()
        route = await loop.run_in_executor(None, self.routing.get_next_hop, to_addr)
        if route:
            for peer in self.transport.get_peers():
                if peer["address"] == route:
                    ok = await self.transport.send_message(payload, (peer["ip"], peer["port"]))
                    self.stats["bytes_sent"] += len(payload)
                    return ok

        logger.debug("No route to %s", to_addr[:16])
        return False

    async def _heartbeat_loop(self):
        """Periodically announce our LSA to neighbours."""
        while self.running:
            await asyncio.sleep(_HEARTBEAT_INTERVAL)
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.routing.flood_lsa)
            except Exception as exc:
                logger.debug("LSA flood error: %s", exc)

    async def _routing_sync_loop(self):
        """Periodically sync DHT routing data."""
        while self.running:
            await asyncio.sleep(60.0)
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self.routing.run_dijkstra)
            except Exception as exc:
                logger.debug("Dijkstra error: %s", exc)
