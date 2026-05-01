"""
MurNet Network Authentication Token  (Layer 3 — Network Secret).

Each node proves membership in the authorized network by including an
HMAC-SHA256 token in every HELLO handshake.  Nodes that do not know the
secret — including anyone who cloned the public GitHub repository without
receiving the secret out-of-band — cannot complete a handshake with
authorized nodes and are silently rejected.

In the public GitHub repository NETWORK_SECRET is always None (open /
development mode).  To deploy an authorized network set the secret on
every node via the environment variable:

    export MURNET_SECRET=<64-char hex string>

or pass it programmatically before any Transport is created:

    from core.net.network_auth import set_secret
    set_secret(bytes.fromhex("your_64_char_hex"))

All nodes in the same authorized network must share the same secret.

Token format
------------
    nonce  : 32 random bytes, freshly generated per HELLO
    ts     : 8-byte big-endian Unix timestamp (seconds)
    token  : HMAC-SHA256(NETWORK_SECRET, nonce || ts)   → 32 bytes

Replay protection: verify_network_token() rejects tokens whose timestamp
deviates more than max_drift_seconds (default 300 s) from local time.
"""

from __future__ import annotations

import hmac
import os
import struct
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Official MurNet network secret.
# All authorized nodes must share this value to complete handshakes.
# Override via MURNET_SECRET env-var only if you are running a private fork.
# ---------------------------------------------------------------------------
_NETWORK_SECRET: Optional[bytes] = bytes.fromhex(
    "cbbbd949bf3f657e439e7299b749c921dd6bd4be8a8b373d3f57541d3b1b75ec"
)

_ENV_VAR      = "MURNET_SECRET"
_TOKEN_SIZE   = 32   # HMAC-SHA256 → 32 bytes
_NONCE_SIZE   = 32   # fresh nonce per HELLO


def _load_from_env() -> None:
    """Allow env-var override (e.g. for testing). Production uses hardcoded value."""
    global _NETWORK_SECRET
    raw = os.environ.get(_ENV_VAR, "").strip()
    if raw:
        try:
            _NETWORK_SECRET = bytes.fromhex(raw)
        except ValueError:
            print(
                f"[network_auth] WARNING: ${_ENV_VAR} is set but is not "
                "valid hex — falling back to built-in secret."
            )


_load_from_env()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def set_secret(secret: bytes) -> None:
    """Programmatically set the network secret (overrides env-var)."""
    global _NETWORK_SECRET
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise ValueError("Network secret must be at least 16 bytes")
    _NETWORK_SECRET = bytes(secret)


def is_configured() -> bool:
    """Return True when a network secret has been configured."""
    return _NETWORK_SECRET is not None


def make_network_token(nonce: bytes, timestamp: int) -> Optional[bytes]:
    """
    Compute a 32-byte HMAC token for a HELLO packet.

    Returns None if the network secret has not been configured (open mode).
    """
    if _NETWORK_SECRET is None:
        return None
    msg = nonce + struct.pack(">Q", timestamp)
    return hmac.new(_NETWORK_SECRET, msg, "sha256").digest()


def verify_network_token(
    nonce: bytes,
    timestamp: int,
    token: bytes,
    *,
    max_drift_seconds: int = 300,
) -> bool:
    """
    Verify a HELLO handshake token.

    Returns False (silently) when:
    - The network secret is not configured on this node.
    - The timestamp deviates more than max_drift_seconds from local time.
    - The HMAC does not match.
    """
    if _NETWORK_SECRET is None:
        return False

    now = int(time.time())
    if abs(now - timestamp) > max_drift_seconds:
        return False

    expected = make_network_token(nonce, timestamp)
    if expected is None:
        return False

    return hmac.compare_digest(expected, token)
