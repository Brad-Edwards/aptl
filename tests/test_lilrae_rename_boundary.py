"""Structural regression gates for the APTL-to-LilRAE rename boundary."""

from __future__ import annotations

import csv
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[1]
REVIEW_ROOT = PROJECT_ROOT / "docs" / "reviews" / "962-lilrae-readiness"
IDENTITY_LEDGER = REVIEW_ROOT / "identity-disposition.tsv"
TRACKED_FILE_LEDGER = REVIEW_ROOT / "tracked-file-inventory.tsv"

IDENTITY_COLUMNS = (
    "surface_id",
    "kind",
    "current_identity",
    "locations",
    "semantic_owner",
    "history",
    "disposition",
    "compatibility_boundary",
    "retirement_evidence",
    "coordination_owner",
)
REQUIRED_KINDS = {
    "backend-target",
    "cli",
    "config-env",
    "distribution",
    "historical-record",
    "image-native-resource",
    "import-root",
    "persisted-schema",
    "plugin",
    "product-prose",
    "repository",
    "scenario-pack",
    "state-path",
    "static-route",
    "telemetry",
}
FORBIDDEN_OWNER_CATEGORIES = {
    "experience-mcp",
    "experience-plugin",
    "split-core-experience",
}
CURRENT_DECISION_FILES = (
    REVIEW_ROOT / "README.md",
    REVIEW_ROOT / "migration-inventory.md",
    REVIEW_ROOT / "adr-disposition.md",
    REVIEW_ROOT / "backlog-disposition.md",
    REVIEW_ROOT / "delivery-plan.md",
    PROJECT_ROOT / "docs" / "adrs" / "adr-054-lilrae-core-and-experience-ownership.md",
    PROJECT_ROOT / "docs" / "adrs" / "adr-058-adoption-and-security-release-gates.md",
)
REJECTED_CURRENT_PHRASES = (
    "advanced APTL experience",
    "advanced experience on it",
    "APTL experience evidence",
    "core from its experience code",
    "externalize experience hooks",
    "optional experience packages",
    "research experience",
    "selected experience behavior",
    "selected experience;",
    "split-core-experience",
    "experience-mcp",
    "experience-plugin",
)
EXPECTED_APTL_IMAGE_IDENTITIES = {
    "aptl/generic-systemd-base-debian:latest",
    "aptl/generic-systemd-base:latest",
    "aptl-wazuh-sidecar:local",
}


def _tsv_rows(path: Path) -> tuple[tuple[str, ...], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        return tuple(reader.fieldnames or ()), list(reader)


def test_identity_ledger_has_complete_contract_shape() -> None:
    """Every independently versioned identity has an actionable disposition."""

    columns, rows = _tsv_rows(IDENTITY_LEDGER)

    assert columns == IDENTITY_COLUMNS
    assert REQUIRED_KINDS <= {row["kind"] for row in rows}
    assert len({row["surface_id"] for row in rows}) == len(rows)
    for row in rows:
        assert all(row[column].strip() for column in IDENTITY_COLUMNS)


def test_container_image_identities_have_exact_owners_and_consumers() -> None:
    """Every product or pack image has a concrete migration decision."""

    _, rows = _tsv_rows(IDENTITY_LEDGER)
    image_rows = {
        row["current_identity"]: row
        for row in rows
        if row["surface_id"].endswith("-image")
    }

    assert set(image_rows) == EXPECTED_APTL_IMAGE_IDENTITIES
    for row in image_rows.values():
        assert "*" not in row["current_identity"]
        assert " or " not in row["semantic_owner"].casefold()
        assert "producer" in row["locations"].casefold()
        assert "consumer" in row["locations"].casefold()
        assert "per image" not in row["disposition"].casefold()


def test_tracked_file_ledger_reconciles_the_final_tree() -> None:
    """The #962 ledger remains a complete path inventory after its baseline."""

    columns, rows = _tsv_rows(TRACKED_FILE_LEDGER)
    assert columns == ("path", "proposed_owner", "migration_rule")

    ledger_paths = [row["path"] for row in rows]
    assert len(ledger_paths) == len(set(ledger_paths))
    assert not ({row["proposed_owner"] for row in rows} & FORBIDDEN_OWNER_CATEGORIES)

    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    actual_paths = {line for line in completed.stdout.splitlines() if line}
    assert set(ledger_paths) == actual_paths

    review = (REVIEW_ROOT / "README.md").read_text(encoding="utf-8")
    for evidence in ("1,467", "1,505", "1,508", "38", "d48d2b7e"):
        assert evidence in review


def test_current_decisions_reject_the_false_product_split() -> None:
    """Current records describe identity continuity and TechVault as a pack."""

    current_text = "\n".join(
        path.read_text(encoding="utf-8") for path in CURRENT_DECISION_FILES
    )
    lowered = current_text.casefold()

    for phrase in REJECTED_CURRENT_PHRASES:
        assert phrase.casefold() not in lowered
    assert "one product across a rename" in lowered
    assert "techvault is a scenario pack" in lowered
    assert (
        "APTL-to-LilRAE identity continuity and capability ownership".casefold()
        in lowered
    )


def test_static_route_retirement_and_coordination_are_explicit() -> None:
    """The old project-tree route cannot be retired by absence or implication."""

    ledger = IDENTITY_LEDGER.read_text(encoding="utf-8")
    preflight = (
        PROJECT_ROOT
        / "docs"
        / "architecture"
        / "issue-934-rename-boundary-preflight.md"
    ).read_text(encoding="utf-8")
    combined = f"{ledger}\n{preflight}"

    for evidence in (
        "project-tree",
        "docker-compose.yml",
        "installed-wheel",
        "released",
        "parity",
        "reader",
        "#880",
        "#970",
        "OpenRAE/lilrae#3",
    ):
        assert evidence in combined
