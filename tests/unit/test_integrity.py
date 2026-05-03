"""
Unit tests for core/integrity.py — Layer 1 Build Signing.

Run with:
    python -m pytest tests/unit/test_integrity.py -v
"""

import hashlib
import json
import os
import shutil
import pytest
from pathlib import Path

import core.integrity as integ
from core.integrity import TamperedBuildError, _compute_manifest, _load_signature


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sign_manifest(manifest_bytes: bytes, private_key_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    priv = load_pem_private_key(private_key_pem, password=None)
    return priv.sign(manifest_bytes)


def _generate_keypair():
    """Return (private_key_pem, public_key_bytes)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    return (
        priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        pub.public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


# ---------------------------------------------------------------------------
# _SIGNING_PUBLIC_KEY is embedded
# ---------------------------------------------------------------------------

class TestPublicKeyEmbedded:
    def test_public_key_is_set(self):
        """Official build must have a non-None signing public key."""
        assert integ._SIGNING_PUBLIC_KEY is not None

    def test_public_key_is_32_bytes(self):
        assert len(integ._SIGNING_PUBLIC_KEY) == 32

    def test_public_key_matches_expected(self):
        """Pinned to the official build key."""
        expected = bytes.fromhex(
            "c04d50fd9e195e4a5354e59cea4988044e194f0757d19273ddc9e28c909460fe"
        )
        assert integ._SIGNING_PUBLIC_KEY == expected


# ---------------------------------------------------------------------------
# _compute_manifest
# ---------------------------------------------------------------------------

class TestComputeManifest:
    def test_returns_bytes(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        result = _compute_manifest(tmp_path)
        assert isinstance(result, bytes)

    def test_contains_file_hashes(self, tmp_path):
        content = b"hello = 1\n"
        f = tmp_path / "hello.py"
        f.write_bytes(content)
        manifest_bytes = _compute_manifest(tmp_path)
        manifest = json.loads(manifest_bytes)
        expected_hash = hashlib.sha256(content).hexdigest()
        # Find the entry for hello.py
        matching = [v for k, v in manifest.items() if k.endswith("hello.py")]
        assert matching == [expected_hash]

    def test_deterministic(self, tmp_path):
        (tmp_path / "z.py").write_text("z = 99")
        assert _compute_manifest(tmp_path) == _compute_manifest(tmp_path)

    def test_changes_when_file_modified(self, tmp_path):
        f = tmp_path / "m.py"
        f.write_text("x = 1")
        before = _compute_manifest(tmp_path)
        f.write_text("x = 2")
        after = _compute_manifest(tmp_path)
        assert before != after

    def test_changes_when_file_added(self, tmp_path):
        (tmp_path / "a.py").write_text("a = 1")
        before = _compute_manifest(tmp_path)
        (tmp_path / "b.py").write_text("b = 2")
        after = _compute_manifest(tmp_path)
        assert before != after


# ---------------------------------------------------------------------------
# _load_signature
# ---------------------------------------------------------------------------

class TestLoadSignature:
    def test_returns_none_when_missing(self, tmp_path):
        assert _load_signature(tmp_path) is None

    def test_loads_valid_hex(self, tmp_path):
        sig = os.urandom(64)
        (tmp_path / "BUILD_SIGNATURE").write_text(sig.hex())
        assert _load_signature(tmp_path) == sig

    def test_returns_none_on_invalid_hex(self, tmp_path):
        (tmp_path / "BUILD_SIGNATURE").write_text("not_valid_hex!!!")
        assert _load_signature(tmp_path) is None


# ---------------------------------------------------------------------------
# verify_integrity — full flow with a temporary keypair
# ---------------------------------------------------------------------------

class TestVerifyIntegrity:
    @pytest.fixture()
    def signed_tree(self, tmp_path):
        """
        Creates a minimal fake core/ tree, signs it with a fresh key, and
        returns (core_root, project_root, public_key_bytes).
        """
        core_root    = tmp_path / "core"
        project_root = tmp_path
        core_root.mkdir()
        (core_root / "mod.py").write_text("x = 1\n")

        priv_pem, pub_bytes = _generate_keypair()
        manifest_bytes = _compute_manifest(core_root)
        sig = _sign_manifest(manifest_bytes, priv_pem)
        (project_root / "BUILD_SIGNATURE").write_text(sig.hex())

        return core_root, project_root, pub_bytes

    def test_passes_with_valid_signature(self, signed_tree, monkeypatch):
        core_root, project_root, pub_bytes = signed_tree
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", pub_bytes)
        # Should not raise
        integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_raises_when_file_modified(self, signed_tree, monkeypatch):
        core_root, project_root, pub_bytes = signed_tree
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", pub_bytes)
        # Tamper with a source file
        (core_root / "mod.py").write_text("x = 999  # tampered\n")
        with pytest.raises(TamperedBuildError):
            integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_raises_when_file_added(self, signed_tree, monkeypatch):
        core_root, project_root, pub_bytes = signed_tree
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", pub_bytes)
        (core_root / "extra.py").write_text("evil = True\n")
        with pytest.raises(TamperedBuildError):
            integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_raises_when_file_deleted(self, signed_tree, monkeypatch):
        core_root, project_root, pub_bytes = signed_tree
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", pub_bytes)
        (core_root / "mod.py").unlink()
        with pytest.raises(TamperedBuildError):
            integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_raises_when_signature_missing(self, signed_tree, monkeypatch):
        core_root, project_root, pub_bytes = signed_tree
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", pub_bytes)
        (project_root / "BUILD_SIGNATURE").unlink()
        with pytest.raises(TamperedBuildError, match="not found"):
            integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_raises_with_wrong_public_key(self, signed_tree, monkeypatch):
        core_root, project_root, _ = signed_tree
        _, other_pub = _generate_keypair()
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", other_pub)
        with pytest.raises(TamperedBuildError):
            integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_skipped_when_no_public_key(self, signed_tree, monkeypatch):
        """When _SIGNING_PUBLIC_KEY is None, check is silently skipped."""
        core_root, project_root, _ = signed_tree
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", None)
        # Tamper — but check is off, so no raise
        (core_root / "mod.py").write_text("x = 999\n")
        integ.verify_integrity(core_root=core_root, project_root=project_root)

    def test_raises_on_corrupt_signature_file(self, signed_tree, monkeypatch):
        core_root, project_root, pub_bytes = signed_tree
        monkeypatch.setattr(integ, "_SIGNING_PUBLIC_KEY", pub_bytes)
        (project_root / "BUILD_SIGNATURE").write_text("deadbeef" * 8)  # wrong length
        with pytest.raises(TamperedBuildError):
            integ.verify_integrity(core_root=core_root, project_root=project_root)


# ---------------------------------------------------------------------------
# verify_integrity — against the REAL build (BUILD_SIGNATURE in project root)
# ---------------------------------------------------------------------------

class TestRealBuildSignature:
    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason=(
            "BUILD_SIGNATURE is generated on Linux with LF line endings. "
            "Windows git checkout converts .py files to CRLF, producing "
            "different SHA-256 hashes. Re-sign on Windows to run this test."
        ),
    )
    def test_real_build_passes(self):
        """
        The actual BUILD_SIGNATURE must verify against the real core/ tree.
        This test fails if any core file has been modified without re-signing.
        """
        integ.verify_integrity()

    def test_build_signature_file_exists(self):
        project_root = Path(__file__).parent.parent.parent
        sig_file = project_root / "BUILD_SIGNATURE"
        assert sig_file.exists(), "BUILD_SIGNATURE is missing — run: python tools/sign_build.py --sign"
