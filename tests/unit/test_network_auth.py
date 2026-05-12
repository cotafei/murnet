"""
Unit tests for core/net/network_auth.py — Layer 3 Network Secret.

Run with:
    python -m pytest tests/unit/test_network_auth.py -v
"""

import os
import struct
import time
import hmac
import pytest

import murnet.core.net.network_auth as na


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_nonce() -> bytes:
    return os.urandom(32)


def _expected_token(secret: bytes, nonce: bytes, ts: int) -> bytes:
    return hmac.new(secret, nonce + struct.pack(">Q", ts), "sha256").digest()


# ---------------------------------------------------------------------------
# is_configured
# ---------------------------------------------------------------------------

class TestIsConfigured:
    def test_true_by_default(self):
        """Official build has the secret hardcoded — must be configured."""
        assert na.is_configured() is True

    def test_false_when_secret_cleared(self, monkeypatch):
        monkeypatch.setattr(na, "_NETWORK_SECRET", None)
        assert na.is_configured() is False

    def test_true_after_set_secret(self, monkeypatch):
        monkeypatch.setattr(na, "_NETWORK_SECRET", None)
        na.set_secret(os.urandom(32))
        assert na.is_configured() is True


# ---------------------------------------------------------------------------
# set_secret
# ---------------------------------------------------------------------------

class TestSetSecret:
    def test_sets_secret(self, monkeypatch):
        monkeypatch.setattr(na, "_NETWORK_SECRET", None)
        secret = os.urandom(32)
        na.set_secret(secret)
        assert na._NETWORK_SECRET == secret

    def test_rejects_short_secret(self):
        with pytest.raises(ValueError):
            na.set_secret(b"tooshort")

    def test_rejects_non_bytes(self):
        with pytest.raises((ValueError, TypeError)):
            na.set_secret("not_bytes")  # type: ignore


# ---------------------------------------------------------------------------
# make_network_token
# ---------------------------------------------------------------------------

class TestMakeNetworkToken:
    def test_returns_32_bytes(self):
        nonce = _fresh_nonce()
        token = na.make_network_token(nonce, int(time.time()))
        assert isinstance(token, bytes)
        assert len(token) == 32

    def test_returns_none_when_no_secret(self, monkeypatch):
        monkeypatch.setattr(na, "_NETWORK_SECRET", None)
        token = na.make_network_token(_fresh_nonce(), int(time.time()))
        assert token is None

    def test_deterministic_for_same_inputs(self):
        nonce = _fresh_nonce()
        ts = int(time.time())
        t1 = na.make_network_token(nonce, ts)
        t2 = na.make_network_token(nonce, ts)
        assert t1 == t2

    def test_different_nonces_produce_different_tokens(self):
        ts = int(time.time())
        t1 = na.make_network_token(_fresh_nonce(), ts)
        t2 = na.make_network_token(_fresh_nonce(), ts)
        assert t1 != t2

    def test_different_timestamps_produce_different_tokens(self):
        nonce = _fresh_nonce()
        t1 = na.make_network_token(nonce, 1000)
        t2 = na.make_network_token(nonce, 1001)
        assert t1 != t2

    def test_matches_manual_hmac(self):
        secret = na._NETWORK_SECRET
        if secret is None:
            pytest.skip("No secret configured")
        nonce = _fresh_nonce()
        ts = int(time.time())
        expected = _expected_token(secret, nonce, ts)
        assert na.make_network_token(nonce, ts) == expected


# ---------------------------------------------------------------------------
# verify_network_token
# ---------------------------------------------------------------------------

class TestVerifyNetworkToken:
    def test_valid_token_accepted(self):
        nonce = _fresh_nonce()
        ts = int(time.time())
        token = na.make_network_token(nonce, ts)
        assert token is not None
        assert na.verify_network_token(nonce, ts, token) is True

    def test_wrong_token_rejected(self):
        nonce = _fresh_nonce()
        ts = int(time.time())
        bad_token = os.urandom(32)
        assert na.verify_network_token(nonce, ts, bad_token) is False

    def test_wrong_secret_rejected(self, monkeypatch):
        """Token created with one secret must be rejected by a node with a different secret."""
        nonce = _fresh_nonce()
        ts = int(time.time())
        original_secret = na._NETWORK_SECRET
        if original_secret is None:
            pytest.skip("No secret configured")

        token = na.make_network_token(nonce, ts)

        # Swap to a different secret
        monkeypatch.setattr(na, "_NETWORK_SECRET", os.urandom(32))
        assert na.verify_network_token(nonce, ts, token) is False

    def test_no_secret_always_rejects(self, monkeypatch):
        monkeypatch.setattr(na, "_NETWORK_SECRET", None)
        nonce = _fresh_nonce()
        ts = int(time.time())
        fake_token = os.urandom(32)
        assert na.verify_network_token(nonce, ts, fake_token) is False

    def test_timestamp_drift_too_large_rejected(self):
        nonce = _fresh_nonce()
        old_ts = int(time.time()) - 400  # > 300 s drift
        # Make a token with old timestamp using manual HMAC
        secret = na._NETWORK_SECRET
        if secret is None:
            pytest.skip("No secret configured")
        token = _expected_token(secret, nonce, old_ts)
        assert na.verify_network_token(nonce, old_ts, token) is False

    def test_timestamp_within_drift_accepted(self):
        nonce = _fresh_nonce()
        ts = int(time.time()) - 60  # 60 s ago — within default 300 s window
        token = na.make_network_token(nonce, ts)
        assert token is not None
        assert na.verify_network_token(nonce, ts, token) is True

    def test_future_timestamp_within_drift_accepted(self):
        nonce = _fresh_nonce()
        ts = int(time.time()) + 30  # 30 s in the future (clock skew)
        token = na.make_network_token(nonce, ts)
        assert token is not None
        assert na.verify_network_token(nonce, ts, token) is True

    def test_tampered_nonce_rejected(self):
        nonce = _fresh_nonce()
        ts = int(time.time())
        token = na.make_network_token(nonce, ts)
        bad_nonce = os.urandom(32)
        assert na.verify_network_token(bad_nonce, ts, token) is False

    def test_token_not_reusable_with_different_nonce(self):
        """Token is bound to a specific nonce — cannot be replayed with a different nonce."""
        nonce1 = _fresh_nonce()
        nonce2 = _fresh_nonce()
        ts = int(time.time())
        token = na.make_network_token(nonce1, ts)
        assert na.verify_network_token(nonce2, ts, token) is False


# ---------------------------------------------------------------------------
# env-var loading
# ---------------------------------------------------------------------------

class TestEnvVarLoading:
    def test_env_var_overrides_secret(self, monkeypatch):
        new_secret = os.urandom(32)
        monkeypatch.setenv("MURNET_SECRET", new_secret.hex())
        # Reload env
        na._load_from_env()
        assert na._NETWORK_SECRET == new_secret

    def test_invalid_env_var_ignored(self, monkeypatch):
        original = na._NETWORK_SECRET
        monkeypatch.setenv("MURNET_SECRET", "not_valid_hex!!!")
        na._load_from_env()
        # Secret should remain unchanged (warning printed but secret not replaced)
        assert na._NETWORK_SECRET == original
