"""
Unit tests for MurNet v6.2 EncryptedKeystore.

Run with:
    python -m pytest tests/unit/test_keystore.py -v
"""

import os
import pytest

from murnet.core.identity.keystore import (
    EncryptedKeystore,
    WrongPasswordError,
    WeakPasswordError,
    KeystoreNotFoundError,
    KeystoreError,
)
from murnet.core.identity.crypto import Identity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    return EncryptedKeystore(str(tmp_path))


@pytest.fixture
def identity_bytes():
    """32 bytes — minimal valid identity payload for test purposes."""
    return Identity().to_bytes()


_GOOD_PWD  = "securePass1!"
_WEAK_PWD  = "short"
_WRONG_PWD = "wrongPassword!"


# ===========================================================================
# Basic create / load
# ===========================================================================

class TestKeystoreCreateLoad:

    def test_does_not_exist_before_create(self, store):
        assert not store.exists()

    def test_exists_after_create(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        assert store.exists()

    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="Unix file permissions (0o600) are not enforced on Windows",
    )
    def test_file_permissions_600(self, store, identity_bytes, tmp_path):
        store.create(identity_bytes, _GOOD_PWD)
        path = tmp_path / "identity.key.enc"
        # stat returns octal mode; last 3 digits = owner/group/other
        mode = oct(os.stat(str(path)).st_mode)[-3:]
        assert mode == "600", f"Expected 0o600, got {mode}"

    def test_load_returns_original_bytes(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        loaded = store.load(_GOOD_PWD)
        assert loaded == identity_bytes

    def test_load_wrong_password_raises(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        with pytest.raises(WrongPasswordError):
            store.load(_WRONG_PWD)

    def test_load_empty_password_raises(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        with pytest.raises(WrongPasswordError):
            store.load("")

    def test_create_weak_password_raises(self, store, identity_bytes):
        with pytest.raises(WeakPasswordError):
            store.create(identity_bytes, _WEAK_PWD)

    def test_load_not_found_raises(self, store):
        with pytest.raises(KeystoreNotFoundError):
            store.load(_GOOD_PWD)


# ===========================================================================
# Tamper detection
# ===========================================================================

class TestKeystoreTamperDetection:

    def test_tampered_ciphertext_raises(self, store, identity_bytes, tmp_path):
        """AES-GCM tag should reject tampered ciphertext."""
        import json, base64

        store.create(identity_bytes, _GOOD_PWD)
        path = str(tmp_path / "identity.key.enc")

        with open(path) as fh:
            payload = json.load(fh)

        # Flip one byte in ciphertext
        ct = bytearray(base64.b64decode(payload["ciphertext"]))
        ct[0] ^= 0xFF
        payload["ciphertext"] = base64.b64encode(bytes(ct)).decode()

        with open(path, "w") as fh:
            json.dump(payload, fh)

        with pytest.raises(WrongPasswordError):
            store.load(_GOOD_PWD)

    def test_corrupted_json_raises(self, store, identity_bytes, tmp_path):
        store.create(identity_bytes, _GOOD_PWD)
        path = str(tmp_path / "identity.key.enc")
        with open(path, "w") as fh:
            fh.write("not json at all")

        with pytest.raises(KeystoreError):
            store.load(_GOOD_PWD)


# ===========================================================================
# Change password
# ===========================================================================

class TestKeystoreChangePassword:

    def test_change_password_and_load_with_new(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        store.change_password(_GOOD_PWD, "NewSecurePass2!")
        loaded = store.load("NewSecurePass2!")
        assert loaded == identity_bytes

    def test_old_password_invalid_after_change(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        store.change_password(_GOOD_PWD, "NewSecurePass2!")
        with pytest.raises(WrongPasswordError):
            store.load(_GOOD_PWD)

    def test_change_with_wrong_old_password_raises(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        with pytest.raises(WrongPasswordError):
            store.change_password(_WRONG_PWD, "NewSecurePass2!")

    def test_change_to_weak_password_raises(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        with pytest.raises(WeakPasswordError):
            store.change_password(_GOOD_PWD, "weak")


# ===========================================================================
# Wipe
# ===========================================================================

class TestKeystoreWipe:

    def test_wipe_removes_file(self, store, identity_bytes):
        store.create(identity_bytes, _GOOD_PWD)
        store.wipe()
        assert not store.exists()

    def test_wipe_noop_when_not_exists(self, store):
        store.wipe()  # should not raise


# ===========================================================================
# Multiple different passwords (unique salts)
# ===========================================================================

class TestKeystoreUniqueSalts:

    def test_two_stores_same_password_different_ciphertext(self, tmp_path):
        import json

        ib = Identity().to_bytes()
        s1 = EncryptedKeystore(str(tmp_path / "n1"))
        s2 = EncryptedKeystore(str(tmp_path / "n2"))
        s1.create(ib, _GOOD_PWD)
        s2.create(ib, _GOOD_PWD)

        p1 = json.load(open(str(tmp_path / "n1" / "identity.key.enc")))
        p2 = json.load(open(str(tmp_path / "n2" / "identity.key.enc")))

        # Different random salts → different ciphertexts
        assert p1["salt"] != p2["salt"]
        assert p1["ciphertext"] != p2["ciphertext"]


# ===========================================================================
# Integration with Identity round-trip
# ===========================================================================

class TestKeystoreIdentityRoundTrip:

    def test_identity_survives_encrypt_decrypt(self, tmp_path):
        store = EncryptedKeystore(str(tmp_path))
        original = Identity()
        store.create(original.to_bytes(), _GOOD_PWD)

        loaded_bytes = store.load(_GOOD_PWD)
        restored = Identity.from_bytes(loaded_bytes)

        assert restored.address == original.address
        assert restored.get_public_bytes() == original.get_public_bytes()


# ===========================================================================
# Security hardening (v6.2.1)
# ===========================================================================

class TestKeystoreSecurityHardening:

    def test_wrong_password_has_delay(self, store, identity_bytes):
        """WrongPasswordError must enforce a minimum timing delay."""
        store.create(identity_bytes, _GOOD_PWD)
        start = __import__("time").monotonic()
        with pytest.raises(WrongPasswordError):
            store.load(_WRONG_PWD)
        elapsed = __import__("time").monotonic() - start
        # Argon2id itself takes ~1 s, plus ≥0.5 s delay → expect ≥ 0.4 s total
        assert elapsed >= 0.4, f"Expected delay ≥0.4s, got {elapsed:.2f}s"

    def test_memory_hygiene_no_crash(self, store, identity_bytes):
        """Load must complete without error even after key zeroing."""
        store.create(identity_bytes, _GOOD_PWD)
        result = store.load(_GOOD_PWD)
        assert result == identity_bytes

    def test_version_field_present(self, store, identity_bytes, tmp_path):
        """Saved file must carry version=2."""
        import json
        store.create(identity_bytes, _GOOD_PWD)
        with open(str(tmp_path / "identity.key.enc")) as fh:
            payload = json.load(fh)
        assert payload.get("version") == 2

    def test_unsupported_version_raises(self, store, identity_bytes, tmp_path):
        """Version != 1 or 2 must raise KeystoreError."""
        import json
        store.create(identity_bytes, _GOOD_PWD)
        path = str(tmp_path / "identity.key.enc")
        with open(path) as fh:
            payload = json.load(fh)
        payload["version"] = 99
        with open(path, "w") as fh:
            json.dump(payload, fh)
        with pytest.raises(KeystoreError):
            store.load(_GOOD_PWD)

    def test_v1_migration_in_memory(self, tmp_path, identity_bytes):
        """_migrate_v1_to_v2 must reassemble nonce+ciphertext correctly."""
        import json, base64
        from murnet.core.identity.crypto import derive_key_argon2, secure_random_bytes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        store = EncryptedKeystore(str(tmp_path))
        salt = secure_random_bytes(32)
        nonce = secure_random_bytes(12)
        enc_key, _ = derive_key_argon2(_GOOD_PWD.encode(), salt)
        ciphertext = AESGCM(enc_key).encrypt(nonce, identity_bytes, None)

        # Simulate v1 format: nonce prepended to ciphertext
        v1_payload = {
            "version": 1,
            "salt": base64.b64encode(salt).decode(),
            "ciphertext": base64.b64encode(nonce + ciphertext).decode(),
        }
        path = str(tmp_path / "identity.key.enc")
        with open(path, "w") as fh:
            json.dump(v1_payload, fh)

        loaded = store.load(_GOOD_PWD)
        assert loaded == identity_bytes

    def test_wipe_file_disappears(self, store, identity_bytes):
        """wipe() must remove the file."""
        store.create(identity_bytes, _GOOD_PWD)
        store.wipe()
        assert not store.exists()
