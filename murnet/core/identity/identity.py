"""
MurNet v6.1 — Identity Layer
A thin, clean wrapper over core.crypto.Identity that makes NodeID a first-class concept.
"""

import os
from typing import Optional

from murnet.core.identity.crypto import Identity as _CryptoIdentity, blake2b_hash


class NodeID:
    """A 256-bit node identifier derived from an Ed25519 public key (blake2b-32)."""

    __slots__ = ("_hex",)

    def __init__(self, hex_str: str) -> None:
        if len(hex_str) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_str):
            raise ValueError(f"NodeID must be a 64-char hex string, got: {hex_str!r}")
        self._hex = hex_str.lower()

    # --- constructors ---------------------------------------------------------

    @classmethod
    def from_pubkey(cls, pubkey_bytes: bytes) -> "NodeID":
        """Derive NodeID from a raw 32-byte Ed25519 public key."""
        return cls(blake2b_hash(pubkey_bytes, digest_size=32).hex())

    @classmethod
    def from_bytes(cls, b: bytes) -> "NodeID":
        """Construct from 32 raw bytes."""
        if len(b) != 32:
            raise ValueError(f"Expected 32 bytes, got {len(b)}")
        return cls(b.hex())

    @classmethod
    def from_address(cls, address: str, pubkey_hex: str) -> "NodeID":
        """Construct from a raw Ed25519 pubkey hex string (address is for context only)."""
        return cls.from_pubkey(bytes.fromhex(pubkey_hex))

    # --- dunder ---------------------------------------------------------------

    def __str__(self) -> str:
        return self._hex

    def __repr__(self) -> str:
        return f"NodeID({self._hex[:8]}…)"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, NodeID):
            return self._hex == other._hex
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._hex)

    # --- operations -----------------------------------------------------------

    def distance(self, other: "NodeID") -> int:
        """XOR distance (Kademlia metric)."""
        return int(self._hex, 16) ^ int(other._hex, 16)

    def to_bytes(self) -> bytes:
        """Return the 32 raw bytes."""
        return bytes.fromhex(self._hex)


class NodeIdentity:
    """High-level node identity: wraps _CryptoIdentity and exposes a clean API."""

    def __init__(
        self,
        seed: Optional[bytes] = None,
        private_key_bytes: Optional[bytes] = None,
    ) -> None:
        if private_key_bytes is not None:
            self._crypto = _CryptoIdentity(private_key=private_key_bytes)
        elif seed is not None:
            self._crypto = _CryptoIdentity(seed=seed)
        else:
            self._crypto = _CryptoIdentity()

        self.ed25519_pubkey: bytes = self._crypto.get_public_bytes()          # 32 bytes
        self.x25519_pubkey: bytes = self._crypto.get_x25519_public_bytes()    # 32 bytes
        self.address: str = self._crypto.address                               # base58 str
        self.node_id: NodeID = NodeID.from_pubkey(self.ed25519_pubkey)

    # --- signing / verification -----------------------------------------------

    def sign(self, data: dict) -> str:
        """Sign a dict payload; returns a base64 signature string."""
        return self._crypto.sign(data)

    def verify(self, data: dict, signature: str, pubkey_hex: str) -> bool:
        """Verify a signature against an Ed25519 public key (hex or base64)."""
        return self._crypto.verify(data, signature, pubkey_hex)

    # --- serialization --------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize private key material for storage (64 bytes)."""
        return self._crypto.to_bytes()

    @classmethod
    def from_bytes(cls, b: bytes) -> "NodeIdentity":
        """Deserialize from 64 bytes produced by to_bytes()."""
        crypto = _CryptoIdentity.from_bytes(b)
        instance = cls.__new__(cls)
        instance._crypto = crypto
        instance.ed25519_pubkey = crypto.get_public_bytes()
        instance.x25519_pubkey = crypto.get_x25519_public_bytes()
        instance.address = crypto.address
        instance.node_id = NodeID.from_pubkey(instance.ed25519_pubkey)
        return instance

    # --- info -----------------------------------------------------------------

    def get_contact_info(self) -> dict:
        return {
            "node_id": str(self.node_id),
            "address": self.address,
            "ed25519_pubkey": self.ed25519_pubkey.hex(),
            "x25519_pubkey": self.x25519_pubkey.hex(),
        }

    def __repr__(self) -> str:
        return f"NodeIdentity(node_id={self.node_id!r}, address={self.address!r})"


class IdentityStore:
    """Thin persistence wrapper: load/save a NodeIdentity from/to disk."""

    def __init__(self, data_dir: str) -> None:
        self._path = os.path.join(data_dir, "identity.key")

    def load(self) -> Optional[NodeIdentity]:
        """Return NodeIdentity loaded from disk, or None if the file is absent."""
        try:
            with open(self._path, "rb") as fh:
                return NodeIdentity.from_bytes(fh.read())
        except FileNotFoundError:
            return None

    def save(self, identity: NodeIdentity) -> None:
        """Write identity bytes to disk with owner-only permissions (0o600)."""
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, identity.to_bytes())
        finally:
            os.close(fd)

    def load_or_create(self) -> NodeIdentity:
        """Load existing identity or generate, persist, and return a new one."""
        identity = self.load()
        if identity is None:
            identity = NodeIdentity()
            self.save(identity)
        return identity
