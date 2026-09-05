"""Regression guards for retiring APTL-owned TechVault variant selectors."""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "retired",
    [
        "techvault-attacker-target",
        "techvault-defensive-min",
        "techvault-enterprise-web",
        "techvault-observability-core",
    ],
)
def test_retired_local_variant_is_not_a_pack_alias(retired):
    from aptl.core.scenario_catalog import resolve_scenario_selection

    with pytest.raises(ValueError, match="Available scenarios: techvault"):
        resolve_scenario_selection(PROJECT_ROOT, scenario_id=retired)


def test_full_techvault_pack_is_the_only_catalog_selection():
    from aptl.core.scenario_catalog import load_scenario_catalog

    catalog = load_scenario_catalog(PROJECT_ROOT)
    assert [entry.id for entry in catalog.scenarios] == ["techvault"]
    assert catalog.bundle.pack_identity == catalog.pack_identity
