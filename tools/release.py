#!/usr/bin/env python3
"""Cut an aptl release.

Computes the next version from the pending towncrier fragments in
``changelog.d/``, writes it into ``src/aptl/__init__.py`` (the single version
source of truth), and runs ``towncrier build`` to fold the fragments into
``CHANGELOG.md``. It makes no git commits — you commit the result on a
``release/vX.Y.Z`` branch and open a normal PR to ``main``. Merging that PR
triggers ``.github/workflows/release.yml``, which tags + publishes.

Usage:
    python tools/release.py                 # auto: next version from fragments
    python tools/release.py --version 0.1.0 # explicit (e.g. the first release)

Bump rubric (pre-1.0, i.e. major == 0):
    any added / changed / removed / deprecated  -> minor
    else fixed / security                       -> patch
Once major >= 1, ``removed`` is treated as a breaking major bump.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "src" / "aptl" / "__init__.py"
FRAGMENTS = ROOT / "changelog.d"

_VERSION_RE = re.compile(r'^__version__\s*=\s*"(\d+)\.(\d+)\.(\d+)"', re.MULTILINE)

MINOR_TYPES = {"added", "changed", "deprecated"}
PATCH_TYPES = {"fixed", "security"}
BREAKING_TYPES = {"removed"}


def current_version() -> tuple[int, int, int]:
    m = _VERSION_RE.search(INIT.read_text(encoding="utf-8"))
    if not m:
        sys.exit(f"could not find __version__ = \"X.Y.Z\" in {INIT}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def pending_fragment_types() -> set[str]:
    types: set[str] = set()
    for f in FRAGMENTS.glob("*.md"):
        if f.name.startswith("_"):  # _template.md.jinja et al.
            continue
        parts = f.name.split(".")
        if len(parts) >= 3:  # <slug>.<type>.md
            types.add(parts[-2])
    return types


def next_version(cur: tuple[int, int, int], types: set[str]) -> str | None:
    major, minor, patch = cur
    if types & BREAKING_TYPES:
        if major >= 1:
            return f"{major + 1}.0.0"
        return f"{major}.{minor + 1}.0"  # pre-1.0: breaking is a minor
    if types & MINOR_TYPES:
        return f"{major}.{minor + 1}.0"
    if types & PATCH_TYPES:
        return f"{major}.{minor}.{patch + 1}"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cut an aptl release.")
    parser.add_argument("--version", help="explicit version (skip auto-compute)")
    args = parser.parse_args(argv)

    types = pending_fragment_types()
    if args.version:
        version = args.version
    else:
        if not types:
            sys.exit("no changelog fragments in changelog.d/ — nothing to release")
        version = next_version(current_version(), types)
        if version is None:
            sys.exit(f"fragment types {sorted(types)} imply no release")

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"invalid version {version!r} (expected X.Y.Z)")

    # 1. write the single version source of truth
    text = INIT.read_text(encoding="utf-8")
    text = _VERSION_RE.sub(f'__version__ = "{version}"', text, count=1)
    INIT.write_text(text, encoding="utf-8")

    # 2. fold fragments into CHANGELOG.md
    subprocess.run(
        [sys.executable, "-m", "towncrier", "build", "--yes", "--version", version],
        cwd=ROOT,
        check=True,
    )

    print(f"\nPrepared release v{version}. Next:")
    print(f"  git switch -c release/v{version}")
    print(f'  git commit -am "chore: release v{version}"')
    print(f'  gh pr create --base main --title "chore: release v{version}" --fill')
    print("Merging that PR tags v%s and publishes to PyPI." % version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
