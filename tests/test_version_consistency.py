"""Guard: ``aptl.__version__`` must equal pyproject.toml's ``[project].version``.

Regression test for the CLI reporting a stale version. release-please's python
updater rewrites ``pyproject.toml`` but not the src-layout
``src/aptl/__init__.py``, so the two drifted (pyproject 4.1.1 while
``__version__`` stayed 4.0.0) and ``aptl --version`` reported the wrong value on
a real PyPI install. release-please now bumps both (``extra-files`` +
``x-release-please-version`` annotation); this test fails if they drift again.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import aptl

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_version_matches_pyproject() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert aptl.__version__ == data["project"]["version"], (
        f"aptl.__version__={aptl.__version__!r} != pyproject "
        f"version={data['project']['version']!r}; release-please must bump both "
        "(release-please-config.json extra-files + the x-release-please-version "
        "annotation in src/aptl/__init__.py)"
    )
