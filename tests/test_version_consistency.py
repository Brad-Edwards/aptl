"""Guard: ``aptl.__version__`` must equal pyproject.toml's ``[project].version``.

Regression test for the CLI reporting a stale version. release-please's python
updater rewrites ``pyproject.toml`` but not the src-layout
``src/aptl/__init__.py``, so the two drifted (pyproject 4.1.1 while
``__version__`` stayed 4.0.0) and ``aptl --version`` reported the wrong value on
a real PyPI install. release-please now bumps both (``extra-files`` +
``x-release-please-version`` annotation); this test fails if they drift again.

The same drift hit ``uv.lock``: release-please left the lockfile's own
``aptl-labs`` entry at 5.5.0 after the 5.6.0 release, so the ``uv-lock``
pre-commit hook failed on the dev->main promotion. release-please now bumps the
lockfile via a ``toml`` extra-file; the tests below pin that config and the
lockfile/pyproject agreement.
"""

from __future__ import annotations

import json
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


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_uv_lock_matches_pyproject() -> None:
    project = _pyproject()["project"]
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = [p["version"] for p in lock["package"] if p["name"] == project["name"]]
    assert locked == [project["version"]], (
        f"uv.lock {project['name']} version={locked!r} != pyproject "
        f"version={project['version']!r}; release-please must bump uv.lock too "
        "(release-please-config.json toml extra-file)"
    )


def test_release_please_bumps_uv_lock() -> None:
    config = json.loads(
        (REPO_ROOT / "release-please-config.json").read_text(encoding="utf-8")
    )
    name = _pyproject()["project"]["name"]
    assert {
        "type": "toml",
        "path": "uv.lock",
        "jsonpath": f"$.package[?(@.name.value=='{name}')].version",
    } in config["packages"]["."]["extra-files"]
