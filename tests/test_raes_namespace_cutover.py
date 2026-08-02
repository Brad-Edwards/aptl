"""Regression gates for the hard RAES Python namespace cutover."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import raes

PROJECT_ROOT = Path(__file__).parents[1]
LEGACY_IMPORT_ROOTS = frozenset(
    {
        "aces_backend_protocols",
        "aces_conformance",
        "aces_contracts",
        "aces_operations",
        "aces_processor",
        "aces_runtime",
        "aces_sdl",
    }
)


def test_project_depends_on_exact_raes_3_3_release() -> None:
    """The qualified backend and semantic freeze use the same RAES release."""

    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())

    assert "raes==3.3.0" in project["project"]["dependencies"]
    assert all(
        not dependency.startswith("aces-sdl")
        for dependency in project["project"]["dependencies"]
    )
    assert raes.__version__ == "3.3.0"


def test_runtime_and_tests_do_not_import_removed_aces_packages() -> None:
    """RAES 3.1 ships no compatibility aliases for the old Python packages."""

    offenders: list[str] = []
    for root in (PROJECT_ROOT / "src", PROJECT_ROOT / "tests"):
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = {alias.name.split(".", 1)[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported = {node.module.split(".", 1)[0]}
                else:
                    continue
                legacy = sorted(imported & LEGACY_IMPORT_ROOTS)
                if legacy:
                    offenders.append(
                        f"{path.relative_to(PROJECT_ROOT)}:{node.lineno}:"
                        + ",".join(legacy)
                    )

    assert offenders == []
