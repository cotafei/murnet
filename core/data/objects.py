"""
MurNet v6.2 — Object System

Content-addressable, signed immutable objects.  Every object is identified by
the Blake2b-256 hash of its canonical (sorted-keys) JSON representation, so the
ID is a commitment to the content.

Structure of a MurObject on the wire::

    {
        "id":        "<64-char blake2b-256 hex>",
        "type":      "<application-defined string, e.g. 'msg' / 'profile'>",
        "owner":     "<base58 node address of the creator>",
        "timestamp": 1712345678.123,
        "data":      { ... arbitrary JSON payload ... },
        "signature": "<base64-encoded Ed25519 signature of canonical_bytes>"
    }

The canonical representation used for signing and ID computation is produced by
``MurObject.canonical_bytes()``: JSON with sorted keys and no whitespace, with
the ``"signature"`` field excluded.  This makes signatures deterministic and
re-verifiable by any peer that holds the author's public key.

Typical usage::

    from core.objects import ObjectStore, MurObject

    store = ObjectStore("./data")
    obj = MurObject.create(
        obj_type="msg",
        owner=node.address,
        data={"text": "Hello!", "to": "1RecipAddr..."},
        identity=node.identity,
    )
    store.put(obj)

    loaded = store.get(obj.id)
    assert loaded == obj
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from hashlib import blake2b
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Maximum payload size for a single object (256 KB)
MAX_OBJECT_SIZE = 256 * 1024
# How many objects to keep in the in-memory LRU cache
_CACHE_SIZE = 512


# ---------------------------------------------------------------------------
# MurObject
# ---------------------------------------------------------------------------


@dataclass
class MurObject:
    """
    An immutable, content-addressable, signed object.

    Fields
    ------
    id        -- 64-char hex Blake2b-256 hash of canonical_bytes()
    type      -- application-level type tag (e.g. ``"msg"``, ``"profile"``)
    owner     -- base58 address of the creating node
    timestamp -- UNIX timestamp (float) of creation
    data      -- arbitrary JSON-serialisable payload (dict)
    signature -- base64 Ed25519 signature of canonical_bytes() (empty if unsigned)
    """

    id: str
    type: str
    owner: str
    timestamp: float
    data: Dict[str, Any]
    signature: str = ""

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        obj_type: str,
        owner: str,
        data: Dict[str, Any],
        identity=None,
        timestamp: Optional[float] = None,
    ) -> "MurObject":
        """
        Build and (optionally) sign a new MurObject.

        Parameters
        ----------
        obj_type  : str           — type tag
        owner     : str           — base58 address of creator
        data      : dict          — payload (must be JSON-serialisable)
        identity  : NodeIdentity  — if provided, the object is signed with Ed25519
        timestamp : float|None    — override creation time (default: now)
        """
        ts = timestamp if timestamp is not None else time.time()

        # Compute ID from unsigned canonical form first
        proto = cls(id="", type=obj_type, owner=owner, timestamp=ts, data=data)
        obj_id = proto._compute_id()

        obj = cls(id=obj_id, type=obj_type, owner=owner, timestamp=ts, data=data)

        if identity is not None:
            sig_bytes = identity._crypto.private_key.sign(obj.canonical_bytes())
            obj.signature = base64.b64encode(sig_bytes).decode()

        return obj

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "type":      self.type,
            "owner":     self.owner,
            "timestamp": self.timestamp,
            "data":      self.data,
            "signature": self.signature,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode()

    def canonical_bytes(self) -> bytes:
        """
        Deterministic byte representation used for signing and ID computation.
        Excludes the ``signature`` field; keys are sorted; no whitespace.
        """
        d = {
            "data":      self.data,
            "id":        self.id,
            "owner":     self.owner,
            "timestamp": self.timestamp,
            "type":      self.type,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_dict(cls, d: dict) -> "MurObject":
        """Deserialise from a plain dict (e.g. parsed from JSON)."""
        required = ("id", "type", "owner", "timestamp", "data")
        for key in required:
            if key not in d:
                raise ValueError(f"MurObject missing required field: {key!r}")
        return cls(
            id=str(d["id"]),
            type=str(d["type"]),
            owner=str(d["owner"]),
            timestamp=float(d["timestamp"]),
            data=dict(d["data"]),
            signature=str(d.get("signature", "")),
        )

    @classmethod
    def from_bytes(cls, b: bytes) -> "MurObject":
        return cls.from_dict(json.loads(b.decode()))

    # ------------------------------------------------------------------
    # Integrity helpers
    # ------------------------------------------------------------------

    def _compute_id(self) -> str:
        """Compute Blake2b-256 hex hash of canonical representation (without id field)."""
        canonical = json.dumps(
            {
                "data":      self.data,
                "owner":     self.owner,
                "timestamp": self.timestamp,
                "type":      self.type,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return blake2b(canonical, digest_size=32).hexdigest()

    def verify_id(self) -> bool:
        """Return True if the id field matches the content hash."""
        return self.id == self._compute_id()

    def verify_signature(self, pubkey_hex: str) -> bool:
        """
        Verify the Ed25519 signature against the owner's public key.

        Parameters
        ----------
        pubkey_hex : 64-char hex Ed25519 public key of the claimed owner
        """
        if not self.signature:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
            sig_bytes = base64.b64decode(self.signature)
            pub.verify(sig_bytes, self.canonical_bytes())
            return True
        except Exception:
            return False

    def is_valid(self, pubkey_hex: Optional[str] = None) -> bool:
        """
        Quick validity check.

        Verifies the content hash (always) and the signature (when *pubkey_hex*
        is supplied).
        """
        if not self.verify_id():
            return False
        if pubkey_hex is not None and not self.verify_signature(pubkey_hex):
            return False
        return True

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MurObject):
            return self.id == other.id
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"MurObject(id={self.id[:8]}…, type={self.type!r}, owner={self.owner[:8]}…)"


# ---------------------------------------------------------------------------
# ObjectStore — in-memory + on-disk persistence
# ---------------------------------------------------------------------------


class ObjectStore:
    """
    Hash-addressed object store with optional on-disk persistence.

    Layout on disk::

        <data_dir>/objects/<prefix2>/<id>.json

    The two-char prefix shards the directory to avoid large flat directories
    (same approach as Git's object store).

    The in-memory LRU is a simple dict; objects are evicted in FIFO order
    once the cache exceeds ``_CACHE_SIZE`` entries.
    """

    def __init__(self, data_dir: str, persist: bool = True) -> None:
        self._data_dir = data_dir
        self._persist = persist
        self._objects_dir = os.path.join(data_dir, "objects")
        if persist:
            os.makedirs(self._objects_dir, exist_ok=True)
        # Simple ordered dict acting as LRU cache
        self._cache: Dict[str, MurObject] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def put(self, obj: MurObject) -> bool:
        """
        Store an object.  Returns True if stored, False if it already existed.

        Raises ValueError if the object fails the basic ID integrity check.
        """
        if not obj.verify_id():
            raise ValueError(f"Object ID mismatch: {obj.id!r} does not match content hash")
        if obj.id in self._cache:
            return False  # already have it

        raw = obj.to_bytes()
        if len(raw) > MAX_OBJECT_SIZE:
            raise ValueError(f"Object too large: {len(raw)} bytes (max {MAX_OBJECT_SIZE})")

        self._cache_put(obj)

        if self._persist:
            self._write_to_disk(obj)

        return True

    def get(self, obj_id: str) -> Optional[MurObject]:
        """Retrieve an object by its hex ID.  Returns None if not found."""
        if obj_id in self._cache:
            return self._cache[obj_id]
        if self._persist:
            return self._read_from_disk(obj_id)
        return None

    def has(self, obj_id: str) -> bool:
        """Return True if the object is locally available."""
        if obj_id in self._cache:
            return True
        if self._persist:
            return os.path.exists(self._obj_path(obj_id))
        return False

    def delete(self, obj_id: str) -> bool:
        """Remove an object.  Returns True if it existed and was removed."""
        removed = self._cache.pop(obj_id, None) is not None
        if self._persist:
            path = self._obj_path(obj_id)
            if os.path.exists(path):
                os.remove(path)
                removed = True
        return removed

    def list_ids(self) -> List[str]:
        """Return all known object IDs (from cache + disk)."""
        ids = set(self._cache.keys())
        if self._persist and os.path.isdir(self._objects_dir):
            for prefix_dir in os.listdir(self._objects_dir):
                prefix_path = os.path.join(self._objects_dir, prefix_dir)
                if os.path.isdir(prefix_path):
                    for fname in os.listdir(prefix_path):
                        if fname.endswith(".json"):
                            ids.add(fname[:-5])
        return list(ids)

    def list_by_type(self, obj_type: str) -> List[MurObject]:
        """Return all locally stored objects of a given type."""
        result = []
        for obj_id in self.list_ids():
            obj = self.get(obj_id)
            if obj is not None and obj.type == obj_type:
                result.append(obj)
        return result

    def stats(self) -> dict:
        return {
            "cached": len(self._cache),
            "persist": self._persist,
            "disk_count": len(self.list_ids()) if self._persist else 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _obj_path(self, obj_id: str) -> str:
        prefix = obj_id[:2]
        return os.path.join(self._objects_dir, prefix, f"{obj_id}.json")

    def _write_to_disk(self, obj: MurObject) -> None:
        path = self._obj_path(obj.id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(obj.to_dict(), fh)
        except OSError as exc:
            logger.warning("ObjectStore: failed to persist %s: %s", obj.id[:8], exc)

    def _read_from_disk(self, obj_id: str) -> Optional[MurObject]:
        path = self._obj_path(obj_id)
        try:
            with open(path, encoding="utf-8") as fh:
                obj = MurObject.from_dict(json.load(fh))
            self._cache_put(obj)
            return obj
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.warning("ObjectStore: failed to read %s: %s", obj_id[:8], exc)
            return None

    def _cache_put(self, obj: MurObject) -> None:
        """Insert into cache; evict oldest entry if over capacity."""
        if len(self._cache) >= _CACHE_SIZE and obj.id not in self._cache:
            # Evict first (oldest) entry
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[obj.id] = obj
