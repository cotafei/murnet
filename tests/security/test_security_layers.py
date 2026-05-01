"""
Security layer integration tests — Layer 1 + Layer 3.

Tests that verify:
- Transport rejects HELLO without a valid network token (Layer 3)
- Transport accepts HELLO with a correct network token
- TamperedBuildError is raised when source is modified (Layer 1)
- BUILD_SIGNATURE is present and valid for current codebase

Run with:
    python -m pytest tests/security/test_security_layers.py -v
"""

import hashlib
import json
import os
import struct
import time
import hmac
import pytest
from pathlib import Path
from unittest.mock import patch

import core.net.network_auth as na
import core.integrity as integ
from core.integrity import TamperedBuildError


# ===========================================================================
# Layer 3 — Network Secret: Transport-level rejection
# ===========================================================================

class TestTransportNetworkAuth:
    """
    Unit tests that verify _handle_hello() in Transport rejects connections
    when network_auth.is_configured() is True and the token is missing / wrong.
    """

    @pytest.fixture()
    def transport(self):
        from core.net.transport import Transport
        t = Transport(port=0)
        t._node_address = "test_node"
        t._public_key   = os.urandom(32)
        t._private_key  = os.urandom(32)
        return t

    def _hello_payload(self, with_token: bool = True, bad_token: bool = False) -> bytes:
        nonce = os.urandom(32)
        ts    = int(time.time())
        data  = {
            "version":    "5.0-secure",
            "address":    "peer_node",
            "public_key": os.urandom(32).hex(),
            "timestamp":  ts,
            "capabilities": ["auth"],
        }
        if with_token:
            token = na.make_network_token(nonce, ts)
            if bad_token:
                token = os.urandom(32)   # random garbage
            data["net_nonce"] = nonce.hex()
            data["net_token"] = token.hex()
        return json.dumps(data).encode()

    def test_hello_with_valid_token_creates_peer(self, transport):
        payload = self._hello_payload(with_token=True)
        addr    = ("127.0.0.1", 9999)
        transport._handle_hello(payload, addr)
        assert len(transport.peers) == 1

    def test_hello_without_token_rejected_when_secret_configured(self, transport):
        payload = self._hello_payload(with_token=False)
        addr    = ("127.0.0.1", 9999)
        transport._handle_hello(payload, addr)
        # Peer must NOT have been created
        assert len(transport.peers) == 0

    def test_hello_with_bad_token_rejected(self, transport):
        payload = self._hello_payload(with_token=True, bad_token=True)
        addr    = ("127.0.0.1", 9999)
        transport._handle_hello(payload, addr)
        assert len(transport.peers) == 0

    def test_hello_accepted_in_open_mode(self, transport, monkeypatch):
        """When secret is None (open mode) a tokenless HELLO must be accepted."""
        monkeypatch.setattr(na, "_NETWORK_SECRET", None)
        payload = self._hello_payload(with_token=False)
        addr    = ("127.0.0.1", 9999)
        transport._handle_hello(payload, addr)
        assert len(transport.peers) == 1

    def test_hello_with_expired_timestamp_rejected(self, transport):
        """Token with timestamp > 300 s old must be rejected."""
        secret = na._NETWORK_SECRET
        if secret is None:
            pytest.skip("No secret configured")
        nonce  = os.urandom(32)
        old_ts = int(time.time()) - 400
        token  = hmac.new(secret, nonce + struct.pack(">Q", old_ts), "sha256").digest()
        data   = {
            "version":    "5.0-secure",
            "address":    "peer_node",
            "public_key": os.urandom(32).hex(),
            "timestamp":  old_ts,
            "capabilities": [],
            "net_nonce":  nonce.hex(),
            "net_token":  token.hex(),
        }
        transport._handle_hello(json.dumps(data).encode(), ("127.0.0.1", 9999))
        assert len(transport.peers) == 0

    def test_wrong_secret_on_peer_side_rejected(self, transport, monkeypatch):
        """
        Token created by a peer with a DIFFERENT secret must be rejected.
        """
        # Peer computes token with an alien secret
        alien_secret = os.urandom(32)
        nonce  = os.urandom(32)
        ts     = int(time.time())
        token  = hmac.new(alien_secret, nonce + struct.pack(">Q", ts), "sha256").digest()
        data   = {
            "version":    "5.0-secure",
            "address":    "peer_node",
            "public_key": os.urandom(32).hex(),
            "timestamp":  ts,
            "capabilities": [],
            "net_nonce":  nonce.hex(),
            "net_token":  token.hex(),
        }
        transport._handle_hello(json.dumps(data).encode(), ("127.0.0.1", 9999))
        assert len(transport.peers) == 0


# ===========================================================================
# Layer 1 — Build Integrity
# ===========================================================================

class TestBuildIntegrityLayer:
    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="BUILD_SIGNATURE generated on Linux; CRLF checkout breaks hashes on Windows",
    )
    def test_real_build_signature_is_valid(self):
        """
        The BUILD_SIGNATURE committed to the repo must verify against the
        current core/ source tree using the embedded public key.
        """
        integ.verify_integrity()   # raises TamperedBuildError on failure

    def test_signing_public_key_is_embedded(self):
        assert integ._SIGNING_PUBLIC_KEY is not None
        assert len(integ._SIGNING_PUBLIC_KEY) == 32

    def test_tampered_file_detected(self, tmp_path, monkeypatch):
        """Modifying any .py file must cause verify_integrity to raise."""
        core_root    = tmp_path / "core"
        project_root = tmp_path
        core_root.mkdir()
        (core_root / "safe.py").write_text("x = 1\n")

        # Sign the clean tree with a fresh throwaway key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption,
        )
        priv    = Ed25519PrivateKey.generate()
        pub     = priv.public_key()
        pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        manifest_bytes = integ._compute_manifest(core_root)
        sig = priv.sign(manifest_bytes)
        (project_root / "BUILD_SIGNATURE").write_text(sig.hex())

        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", pub_raw)

        # Sanity: unmodified tree passes
        integ.verify_integrity(core_root=core_root, project_root=project_root)

        # Tamper
        (core_root / "safe.py").write_text("x = 999  # injected\n")
        with pytest.raises(TamperedBuildError):
            integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_missing_signature_file_detected(self, tmp_path, monkeypatch):
        core_root    = tmp_path / "core"
        project_root = tmp_path
        core_root.mkdir()
        (core_root / "mod.py").write_text("y = 2\n")
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", os.urandom(32))
        with pytest.raises(TamperedBuildError, match="not found"):
            integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_no_public_key_skips_check(self, tmp_path, monkeypatch):
        core_root    = tmp_path / "core"
        project_root = tmp_path
        core_root.mkdir()
        (core_root / "mod.py").write_text("evil = True\n")
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", None)
        # Must not raise even without BUILD_SIGNATURE
        integ.verify_integrity(core_root=core_root, project_root=project_root)


# ===========================================================================
# Layer 3 + Layer 1 combined: hardcoded values are correct
# ===========================================================================

class TestHardcodedValues:
    def test_network_secret_is_64_hex_chars(self):
        secret = na._NETWORK_SECRET
        assert secret is not None
        assert len(secret) == 32   # 32 bytes = 64 hex chars

    def test_signing_key_is_32_bytes(self):
        assert integ._SIGNING_PUBLIC_KEY is not None
        assert len(integ._SIGNING_PUBLIC_KEY) == 32

    def test_network_token_roundtrip(self):
        """End-to-end: make a token, verify it — must pass."""
        nonce = os.urandom(32)
        ts    = int(time.time())
        token = na.make_network_token(nonce, ts)
        assert token is not None
        assert na.verify_network_token(nonce, ts, token) is True

    def test_build_signature_exists_in_project(self):
        project_root = Path(__file__).parent.parent.parent
        assert (project_root / "BUILD_SIGNATURE").exists(), (
            "BUILD_SIGNATURE missing — run: python tools/sign_build.py --sign --key-file build_key.pem"
        )
