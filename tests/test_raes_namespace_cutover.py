"""Regression gates for the hard RAES Python namespace cutover."""

from __future__ import annotations

import ast
import csv
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
IDENTITY_LEDGER = (
    PROJECT_ROOT
    / "docs"
    / "reviews"
    / "962-lilrae-readiness"
    / "identity-disposition.tsv"
)
KNOWN_PRIVATE_RAES_IMPORTS = {
    (
        "src/aptl/backends/raes_artifact_availability.py",
        "raes._source",
        "ArtifactIdentity",
    ),
    (
        "src/aptl/backends/raes_artifact_availability.py",
        "raes_processor.compiler.addresses",
        "_node_address",
    ),
    (
        "src/aptl/backends/raes_runtime_orchestration.py",
        "raes_processor.compiler.addresses",
        "_node_address",
    ),
    (
        "src/aptl/backends/raes_repro.py",
        "raes_runtime.control_plane_store",
        "_snapshot_payload",
    ),
}


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


def test_private_raes_imports_and_manifest_fallback_are_inventoried() -> None:
    """Known public-API blockers stay explicit until upstream replacements land."""

    observed: set[tuple[str, str, str]] = set()
    source_root = PROJECT_ROOT / "src" / "aptl"
    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if not node.module.startswith(("raes.", "raes_")):
                continue
            if "._" not in node.module and not any(
                alias.name.startswith("_") for alias in node.names
            ):
                continue
            observed.update(
                (
                    str(path.relative_to(PROJECT_ROOT)),
                    node.module,
                    alias.name,
                )
                for alias in node.names
            )

    assert observed == KNOWN_PRIVATE_RAES_IMPORTS

    with IDENTITY_LEDGER.open(newline="", encoding="utf-8") as stream:
        rows = {
            row["surface_id"]: row for row in csv.DictReader(stream, delimiter="\t")
        }

    expected_rows = {
        "raes-private-artifact-identity": "raes._source.ArtifactIdentity",
        "raes-private-node-address": "raes_processor.compiler.addresses._node_address",
        "raes-private-snapshot-payload": "raes_runtime.control_plane_store._snapshot_payload",
        "raes-manifest-authority-fallback": "BACKEND_SUPPORTED_CONTRACT_IDS ImportError fallback",
    }
    for surface_id, identity in expected_rows.items():
        assert rows[surface_id]["current_identity"] == identity

    manifest = (
        PROJECT_ROOT / "src" / "aptl" / "backends" / "raes_manifest.py"
    ).read_text()
    assert (
        "from raes_contracts.manifest_authority import BACKEND_SUPPORTED_CONTRACT_IDS"
        in manifest
    )
    assert "except ImportError:" in manifest
