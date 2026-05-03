"""
MurNet Build Integrity Verification  (Layer 1 — Binary Signing).

Verifies that the source tree has not been modified since the last official
build signing.  When _SIGNING_PUBLIC_KEY is None (dev / open-source builds)
the check is skipped transparently — no error, no warning.

Workflow
--------
1. Generate a key pair once (keep private key **offline and secret**):

       python tools/sign_build.py --generate-key --key-file build_key.pem

2. Embed the printed public-key hex into this file:

       _SIGNING_PUBLIC_KEY = bytes.fromhex("<64-char hex>")

3. Sign every official release before distributing:

       python tools/sign_build.py --sign --key-file build_key.pem

   This writes BUILD_SIGNATURE in the project root.

4. At node startup call verify_integrity() (e.g. in cli.py or __main__.py):

       from core.integrity import verify_integrity, TamperedBuildError
       verify_integrity()   # raises TamperedBuildError if tampered

Threat model
------------
- Protects against silent modification of source files before/after
  distribution (e.g. someone replacing crypto.py on a server).
- Does NOT protect against an attacker who also replaces this file or
  BUILD_SIGNATURE — deploy as a compiled .pyd/.so via setup_cython.py for
  stronger protection.
- Rebuild and re-sign after every legitimate code change.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Official MurNet build signing public key.
# Only builds signed with the corresponding private key will pass verification.
# ---------------------------------------------------------------------------
_SIGNING_PUBLIC_KEY: Optional[bytes] = bytes.fromhex(
    "c04d50fd9e195e4a5354e59cea4988044e194f0757d19273ddc9e28c909460fe"
)


class TamperedBuildError(RuntimeError):
    """Raised when the build integrity check fails."""


def _compute_manifest(core_root: Path) -> bytes:
    manifest: dict = {}
    for p in sorted(core_root.rglob("*.py")):
        # Always use forward slashes so the manifest is identical on all platforms
        rel = p.relative_to(core_root.parent).as_posix()
        manifest[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return json.dumps(manifest, sort_keys=True).encode()


def _load_signature(project_root: Path) -> Optional[bytes]:
    sig_file = project_root / "BUILD_SIGNATURE"
    if sig_file.exists():
        try:
            return bytes.fromhex(sig_file.read_text().strip())
        except ValueError:
            return None
    return None


def verify_integrity(
    core_root: Optional[Path] = None,
    project_root: Optional[Path] = None,
) -> None:
    """
    Verify the integrity of the core source tree against the stored signature.

    Raises TamperedBuildError on verification failure.
    Returns silently when _SIGNING_PUBLIC_KEY is None (dev / open-source mode).
    """
    if _SIGNING_PUBLIC_KEY is None:
        return  # Dev / open-source mode — check disabled

    if core_root is None:
        core_root = Path(__file__).parent
    if project_root is None:
        project_root = core_root.parent

    sig = _load_signature(project_root)
    if sig is None:
        raise TamperedBuildError(
            "BUILD_SIGNATURE not found.  "
            "The build was not signed or the signature file was removed."
        )

    manifest_bytes = _compute_manifest(core_root)

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(_SIGNING_PUBLIC_KEY)
        pub.verify(sig, manifest_bytes)
    except Exception as exc:
        raise TamperedBuildError(f"Build integrity check failed: {exc}") from exc
