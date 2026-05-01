"""
Compile security-critical MurNet modules to native extensions  (Layer 4 — Obfuscation).

Cython compiles the selected Python source files to C and then to a native
shared library (.so on Linux/macOS, .pyd on Windows).  The resulting binary
cannot be read as plain text and is significantly harder to reverse-engineer
than a .py or even a .pyc file.

Python automatically prefers a compiled extension over the .py source when
both exist in the same directory — no other code changes are required.

Targets
-------
All three files in core/identity/ are compiled because they contain the
most security-sensitive logic:

  * crypto.py    — Ed25519 / X25519 / AES-GCM / Argon2id primitives
  * keystore.py  — encrypted private-key storage (Argon2id + AES-GCM)
  * identity.py  — NodeID derivation and signing wrapper

Usage
-----
    pip install cython
    python setup_cython.py build_ext --inplace

After a successful build the compiled files appear alongside the sources:

    core/identity/crypto.cpython-3XX-linux-gnu.so
    core/identity/keystore.cpython-3XX-linux-gnu.so
    core/identity/identity.cpython-3XX-linux-gnu.so

The .py source files can then be deleted from the distributed package;
Python will use the .so files automatically.
"""

from setuptools import setup

try:
    from Cython.Build import cythonize
except ImportError:
    raise SystemExit(
        "Cython is required to build native extensions.\n"
        "Install it with:  pip install cython"
    )

_TARGETS = [
    "core/identity/crypto.py",
    "core/identity/keystore.py",
    "core/identity/identity.py",
]

_COMPILER_DIRECTIVES = {
    "language_level":     "3",
    "boundscheck":        False,
    "wraparound":         False,
    "cdivision":          True,
    "optimize.use_switch": True,
}

setup(
    name="murnet_secure_core",
    ext_modules=cythonize(
        _TARGETS,
        compiler_directives=_COMPILER_DIRECTIVES,
        annotate=False,
        quiet=True,
    ),
    zip_safe=False,
)
