"""
Per-hop cryptography for MurNet Onion Router.

Circuit build: X25519 ECDH → HKDF → 32-byte AES-256-GCM session key.
Cell payload:  hop_encrypt / hop_decrypt using that key.
"""
from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_NONCE_LEN = 12
_KEY_INFO   = b"murnet_onion_v1"


def generate_ephemeral_keypair() -> Tuple[bytes, bytes]:
    """Return (private_bytes_32, public_bytes_32)."""
    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_b, pub_b


def derive_hop_key(local_priv: bytes, remote_pub: bytes) -> bytes:
    """X25519 ECDH + HKDF-SHA256 → 32-byte session key."""
    priv = x25519.X25519PrivateKey.from_private_bytes(local_priv)
    pub  = x25519.X25519PublicKey.from_public_bytes(remote_pub)
    shared = priv.exchange(pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_KEY_INFO,
    ).derive(shared)


def hop_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce (12 B) ‖ ciphertext+tag."""
    nonce = os.urandom(_NONCE_LEN)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def hop_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-GCM decrypt. Expects nonce ‖ ciphertext+tag."""
    if len(data) < _NONCE_LEN + 16:
        raise ValueError(f"Ciphertext too short: {len(data)} bytes")
    return AESGCM(key).decrypt(data[:_NONCE_LEN], data[_NONCE_LEN:], None)
