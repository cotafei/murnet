#!/usr/bin/env python3
"""
MurNet Build Signing Tool  (Layer 1 — Binary Signing).

Usage
-----
Sign the current source tree (requires build_key.pem):

    python tools/sign_build.py --sign --key-file build_key.pem

Verify integrity (no private key needed):

    python tools/sign_build.py --verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT     = Path(__file__).resolve().parent.parent
CORE_DIR = ROOT / "core"
SIG_FILE = ROOT / "BUILD_SIGNATURE"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_manifest(root: Path) -> dict:
    manifest: dict = {}
    for p in sorted(root.rglob("*.py")):
        # Always forward slashes — consistent across Linux, macOS, Windows
        rel = p.relative_to(root.parent).as_posix()
        manifest[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return manifest


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_sign(key_file: Path) -> None:
    """Sign the current core/ source tree."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    priv = load_pem_private_key(key_file.read_bytes(), password=None)

    manifest       = _compute_manifest(CORE_DIR)
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    signature      = priv.sign(manifest_bytes)

    SIG_FILE.write_text(signature.hex())
    print(f"Signed {len(manifest)} files.")
    print(f"Signature written  →  {SIG_FILE}")


def cmd_verify() -> None:
    """Verify the current core/ source tree against BUILD_SIGNATURE."""
    sys.path.insert(0, str(ROOT))
    from core.integrity import verify_integrity, TamperedBuildError

    try:
        verify_integrity()
        print("OK — build integrity verified.")
    except TamperedBuildError as exc:
        print(f"FAIL — {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        description="MurNet build signing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--sign",   action="store_true", help="Sign current source tree")
    p.add_argument("--verify", action="store_true", help="Verify build integrity")
    p.add_argument(
        "--key-file", type=Path, default=Path("build_key.pem"),
        help="Path to PEM private key file (default: build_key.pem)",
    )
    args = p.parse_args()

    if args.sign:
        cmd_sign(args.key_file)
    elif args.verify:
        cmd_verify()
    else:
        p.print_help()


if __name__ == "__main__":
    main()
