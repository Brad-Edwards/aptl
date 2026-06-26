"""Schema and coverage checks for the ACES parity inventory (SCN-010).

The inventory at ``docs/aces/parity-inventory.yaml`` is the authoritative
audit surface SCN-010 specification issues (#319-#324) and the cutover PR
must cite when claiming TechVault parity (ADR-035, "Parity Inventory
Boundary"). These tests enforce that the manifest stays a narrow audit
artifact: closed-enum categories, unique row ids, required fields, and
coverage of every legacy surface bucket.
"""

from collections.abc import Mapping
from pathlib import Path

import pytest
import yaml


pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "aces" / "parity-inventory.yaml"

REQUIRED_TOP_LEVEL_KEYS = {
    "schema_version",
    "generated_for",
    "related_adr",
    "categories",
    "surfaces",
    "rows",
}

REQUIRED_ROW_KEYS = {
    "id",
    "surface",
    "legacy_source",
    "legacy_field",
    "category",
    "aces_target",
    "runtime_owner",
    "validation_evidence",
    "blocking_followup",
    "notes",
}

EXPECTED_CATEGORIES = {
    "aces_sdl",
    "aces_schema_profile_gap",
    "aptl_backend_responsibility",
    "validation_gate",
    "cutover_only_archive",
}

EXPECTED_SURFACES = {
    "scenarios_yaml",
    "docker_compose_topology",
    "aptl_config",
    "env_vars_and_secrets",
    "lab_lifecycle",
    "deployment_backend",
    "snapshots_and_runstore",
    "defensive_stack_configs",
    "test_and_validation",
}

# Substrings that must never appear inside a row body. If the inventory
# starts embedding an env-var name immediately followed by ``=``, that is
# almost certainly a real secret value leaking out of ``.env`` and into a
# committed file. The check is intentionally crude — the inventory's own
# rows reference these names as bare identifiers, never as ``NAME=value``.
SECRET_NAME_TOKENS = (
    "API_PASSWORD",
    "WAZUH_CLUSTER_KEY",
    "MISP_API_KEY",
    "THEHIVE_SECRET",
    "SHUFFLE_API_KEY",
)


@pytest.fixture(scope="module")
def inventory() -> Mapping:
    assert INVENTORY_PATH.exists(), (
        f"Parity inventory missing at {INVENTORY_PATH.relative_to(PROJECT_ROOT)}; "
        "SCN-010 cutover review surface requires it (ADR-035)."
    )
    with INVENTORY_PATH.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, Mapping), "Inventory root must be a mapping."
    return data


def test_top_level_keys_present(inventory):
    missing = REQUIRED_TOP_LEVEL_KEYS - set(inventory)
    assert not missing, f"Inventory missing top-level keys: {sorted(missing)}"


def test_schema_version_is_one(inventory):
    assert inventory["schema_version"] == 1


def test_generated_for_targets_scn_010(inventory):
    assert inventory["generated_for"] == "SCN-010"


def test_related_adr_points_at_adr_035(inventory):
    assert inventory["related_adr"] == "docs/adrs/adr-035-aces-sdl-adoption.md"


def test_categories_match_closed_enum(inventory):
    assert set(inventory["categories"]) == EXPECTED_CATEGORIES


def test_surfaces_match_expected_set(inventory):
    assert set(inventory["surfaces"]) == EXPECTED_SURFACES


def test_rows_is_non_empty_list(inventory):
    rows = inventory["rows"]
    assert isinstance(rows, list)
    assert rows, "Inventory must contain at least one row."


def test_every_row_has_required_keys(inventory):
    missing_by_row = {}
    for row in inventory["rows"]:
        assert isinstance(row, Mapping), f"Row is not a mapping: {row!r}"
        missing = REQUIRED_ROW_KEYS - set(row)
        if missing:
            missing_by_row[row.get("id", "<no-id>")] = sorted(missing)
    assert not missing_by_row, f"Rows missing required keys: {missing_by_row}"


def test_row_ids_are_unique(inventory):
    ids = [row["id"] for row in inventory["rows"]]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"Duplicate row ids: {duplicates}"


def test_row_ids_are_stable_anchor_safe(inventory):
    bad = [
        row["id"]
        for row in inventory["rows"]
        if not row["id"] or not all(c.isalnum() or c in ".-_" for c in row["id"])
    ]
    assert not bad, (
        f"Row ids must be ASCII alphanumeric + '.-_' so issues can cite "
        f"them as anchors; offenders: {bad}"
    )


def test_every_row_category_is_valid(inventory):
    bad = {
        row["id"]: row["category"]
        for row in inventory["rows"]
        if row["category"] not in EXPECTED_CATEGORIES
    }
    assert not bad, f"Rows with category outside the closed enum: {bad}"


def test_every_row_surface_is_valid(inventory):
    bad = {
        row["id"]: row["surface"]
        for row in inventory["rows"]
        if row["surface"] not in EXPECTED_SURFACES
    }
    assert not bad, f"Rows with surface outside the declared set: {bad}"


def test_every_declared_surface_has_at_least_one_row(inventory):
    rows_by_surface = {s: 0 for s in EXPECTED_SURFACES}
    for row in inventory["rows"]:
        rows_by_surface[row["surface"]] += 1
    empty = [s for s, n in rows_by_surface.items() if n == 0]
    assert not empty, (
        f"Every declared surface bucket must carry at least one row; "
        f"empty buckets: {empty}"
    )


def test_every_category_has_at_least_one_row(inventory):
    rows_by_cat = {c: 0 for c in EXPECTED_CATEGORIES}
    for row in inventory["rows"]:
        rows_by_cat[row["category"]] += 1
    empty = [c for c, n in rows_by_cat.items() if n == 0]
    assert not empty, (
        f"Every category in the closed enum must carry at least one row "
        f"so the inventory exercises the whole taxonomy; empty: {empty}"
    )


def test_gap_rows_cite_a_followup(inventory):
    """Gap rows must cite a concrete follow-up, not 'n/a'."""
    offenders = []
    for row in inventory["rows"]:
        if row["category"] == "aces_schema_profile_gap":
            followup = row.get("blocking_followup")
            if not followup or str(followup).strip().lower() in {"n/a", "none", ""}:
                offenders.append(row["id"])
    assert not offenders, (
        f"aces_schema_profile_gap rows must name a blocking follow-up "
        f"(issue ref or ACES upstream pointer); offenders: {offenders}"
    )


def test_every_legacy_scenario_yaml_is_covered(inventory):
    """Every archived legacy scenario YAML must appear in legacy_source
    of at least one row in the ``scenarios_yaml`` surface bucket."""
    scenarios_dir = PROJECT_ROOT / "scenarios" / "archive"
    on_disk = {p.name for p in scenarios_dir.glob("*.yaml")}
    cited = {
        Path(row["legacy_source"]).name
        for row in inventory["rows"]
        if row["surface"] == "scenarios_yaml"
        and row["legacy_source"].startswith("scenarios/")
    }
    missing = on_disk - cited
    assert not missing, (
        f"Scenario YAMLs present on disk but not cited by any inventory "
        f"row: {sorted(missing)}"
    )


def test_no_secret_value_leakage(inventory):
    """Defence-in-depth: the inventory must reference secret env-var
    names as bare identifiers, never as ``NAME=value`` pairs."""
    text = INVENTORY_PATH.read_text(encoding="utf-8")
    offenders = [tok for tok in SECRET_NAME_TOKENS if f"{tok}=" in text]
    assert not offenders, (
        f"Possible secret leakage in inventory (env-var name immediately "
        f"followed by '='): {offenders}"
    )
