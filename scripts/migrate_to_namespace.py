"""
Миграция MurNet в namespace `murnet/`.

ЧТО ДЕЛАЕТ:
    1. Создаёт каталог murnet/ с __init__.py
    2. Перемещает core/, api/, mobile/, vds/, vpn/, demos/, cli.py, desktop_app.py,
       murnet_vpn.py, network_viz.py, build_exe.py в murnet/
    3. Во ВСЕХ .py-файлах (включая tests/) заменяет импорты:
         from core.X          -> from murnet.core.X
         from api.X           -> from murnet.api.X
         from mobile.X        -> from murnet.mobile.X
         from vds.X           -> from murnet.vds.X
         from vpn.X           -> from murnet.vpn.X
         from demos.X         -> from murnet.demos.X
         import core.X        -> import murnet.core.X
         (и аналогично для прочих верхне-уровневых пакетов)
    4. Корневой __init__.py не нужен (он сейчас пустой, удаляется)

ЧТО НЕ ТРОГАЕТ:
    - tests/ остаётся на месте (не часть пакета)
    - scripts/, website/, browser_rs/, docs/, configs/ — не трогаются
    - .claude/worktrees/ — не трогаются
    - VDS systemd-юниты — не трогаются (это отдельная задача деплоя)

РЕЖИМЫ:
    python scripts/migrate_to_namespace.py --dry-run   # ничего не меняет, печатает план
    python scripts/migrate_to_namespace.py --apply     # выполняет миграцию

БЕЗОПАСНОСТЬ:
    Перед --apply сделай:
        git checkout -b refactor/pip-package
        git add -A && git commit -m "snapshot before namespace migration"
    Если что-то сломалось — `git reset --hard HEAD~1` откатит.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG  = ROOT / "murnet"

# Папки/файлы, которые становятся подмодулями `murnet`.
MOVE_DIRS  = ["core", "api", "mobile", "vds", "vpn", "demos"]
MOVE_FILES = ["cli.py", "desktop_app.py", "murnet_vpn.py", "network_viz.py", "build_exe.py"]

# Корневые имена, чьи импорты должны переписаться в `murnet.<name>`.
RENAME = MOVE_DIRS + [Path(f).stem for f in MOVE_FILES]

# Файлы, в которых нужно править импорты (включая tests/).
PY_GLOBS = ["murnet/**/*.py", "tests/**/*.py", "scripts/**/*.py"]

# Регэкспы для переписывания импортов.
def _build_patterns() -> list[tuple[re.Pattern, str]]:
    patterns: list[tuple[re.Pattern, str]] = []
    for name in RENAME:
        # from <name>            -> from murnet.<name>
        # from <name>.X import Y -> from murnet.<name>.X import Y
        patterns.append((
            re.compile(rf"^(\s*)from\s+{name}(\.|\s+import)", re.MULTILINE),
            rf"\1from murnet.{name}\2",
        ))
        # import <name>          -> import murnet.<name> as <name>
        # import <name>.X        -> import murnet.<name>.X
        patterns.append((
            re.compile(rf"^(\s*)import\s+{name}(\.[A-Za-z_][\w.]*)", re.MULTILINE),
            rf"\1import murnet.{name}\2",
        ))
        patterns.append((
            re.compile(rf"^(\s*)import\s+{name}\s*$", re.MULTILINE),
            rf"\1import murnet.{name} as {name}",
        ))
    return patterns

PATTERNS = _build_patterns()


def plan_moves() -> list[tuple[Path, Path]]:
    moves: list[tuple[Path, Path]] = []
    for d in MOVE_DIRS:
        src = ROOT / d
        if src.exists():
            moves.append((src, PKG / d))
    for f in MOVE_FILES:
        src = ROOT / f
        if src.exists():
            moves.append((src, PKG / f))
    return moves


def find_py_files() -> list[Path]:
    files: set[Path] = set()
    for pattern in PY_GLOBS:
        files.update(ROOT.glob(pattern))
    return sorted(files)


def rewrite_imports(text: str) -> tuple[str, int]:
    n = 0
    for pat, repl in PATTERNS:
        new, count = pat.subn(repl, text)
        n += count
        text = new
    return text, n


def do_dry_run() -> None:
    print(f"ROOT: {ROOT}")
    print(f"PKG:  {PKG}\n")

    print("--- MOVES ---")
    for src, dst in plan_moves():
        print(f"  {src.relative_to(ROOT)}  ->  murnet/{dst.relative_to(PKG)}")

    print("\n--- IMPORT REWRITES (PREVIEW, FIRST 20 FILES WITH CHANGES) ---")
    # Сначала виртуально переместим — переписываем импорты в файлах,
    # которые после миграции окажутся в murnet/.
    candidates: list[Path] = []
    for d in MOVE_DIRS:
        candidates.extend((ROOT / d).rglob("*.py"))
    for f in MOVE_FILES:
        p = ROOT / f
        if p.exists():
            candidates.append(p)
    candidates.extend((ROOT / "tests").rglob("*.py"))

    shown = 0
    for fp in candidates:
        try:
            text = fp.read_text(encoding="utf-8")
        except Exception as e:
            print(f"  ! skip {fp}: {e}")
            continue
        _, n = rewrite_imports(text)
        if n > 0:
            print(f"  {fp.relative_to(ROOT)}: {n} replacement(s)")
            shown += 1
            if shown >= 20:
                print("  ... (truncated)")
                break

    print("\n--- ROOT FILES THAT WILL BE REMOVED ---")
    root_init = ROOT / "__init__.py"
    if root_init.exists():
        print(f"  {root_init.relative_to(ROOT)} (empty namespace marker)")

    print("\nDRY-RUN COMPLETE. Use --apply to execute.")


def do_apply() -> None:
    PKG.mkdir(exist_ok=True)
    init_file = PKG / "__init__.py"
    if not init_file.exists():
        init_file.write_text('"""MurNet — decentralized onion-routed P2P network."""\n__version__ = "6.2.0"\n', encoding="utf-8")

    print("[1/3] Moving directories & files into murnet/ ...")
    for src, dst in plan_moves():
        if dst.exists():
            print(f"  SKIP (already exists): {dst.relative_to(ROOT)}")
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        print(f"  moved: {src.relative_to(ROOT)} -> {dst.relative_to(ROOT)}")

    print("\n[2/3] Rewriting imports ...")
    total_files = 0
    total_repl  = 0
    for fp in find_py_files():
        try:
            text = fp.read_text(encoding="utf-8")
        except Exception as e:
            print(f"  ! skip {fp}: {e}")
            continue
        new, n = rewrite_imports(text)
        if n > 0:
            fp.write_text(new, encoding="utf-8")
            print(f"  {fp.relative_to(ROOT)}: {n}")
            total_files += 1
            total_repl  += n
    print(f"  files changed: {total_files}, total replacements: {total_repl}")

    print("\n[3/3] Cleaning root namespace markers ...")
    root_init = ROOT / "__init__.py"
    if root_init.exists() and root_init.stat().st_size < 200:
        root_init.unlink()
        print(f"  removed: {root_init.relative_to(ROOT)}")

    print("\nMIGRATION COMPLETE.")
    print("Next: `pip install -e .` then `pytest tests/unit/ -q`")


def main() -> int:
    ap = argparse.ArgumentParser(description="Migrate MurNet to murnet/ namespace.")
    g  = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true", help="Show plan, change nothing.")
    g.add_argument("--apply",   action="store_true", help="Execute migration.")
    args = ap.parse_args()

    if args.dry_run:
        do_dry_run()
    else:
        do_apply()
    return 0


if __name__ == "__main__":
    sys.exit(main())
