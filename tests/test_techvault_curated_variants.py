"""Static realization proof for the curated TechVault ACES SDL variants (#534).

These exercise the small single-file scenarios registered in
``scenarios/catalog.json`` alongside the default
``scenarios/techvault-operational.sdl.yaml``. Each variant must parse through the
ACES parser, compile through the processor/runtime planner, and realize through
APTL's ``interpret_provisioning_plan`` with no error-severity ``aptl.provisioner.*``
diagnostics, selecting exactly the bounded Compose profile set implied by its
declared node content.

The proofs are content-driven on purpose: realization is asserted from
``interpret_provisioning_plan`` output, the selected profile set is checked
against ``public_start_profiles`` for a config that enables exactly each variant's
profiles, and the anti-collapse / content-not-name tests show the scenario id and
``name`` never drive selection. They run in the fast unit suite (not
``@pytest.mark.integration``): each variant is a handful of nodes, so parse +
compile + realize is cheap, unlike the full TechVault inventory tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from aces_sdl.parser import parse_sdl

from aptl.backends.aces import DEFAULT_ACES_SCENARIO
from aptl.backends.aces_profiles import public_start_profiles, select_backend_profiles
from aptl.core.config import AptlConfig
from aptl.core.scenario_catalog import load_scenario_catalog, resolve_scenario_selection
from aptl.validation._gate_checks import check_parse, check_provisioning_realization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = PROJECT_ROOT / "scenarios"

_CONTAINER_FIELDS = (
    "wazuh",
    "victim",
    "kali",
    "reverse",
    "enterprise",
    "soc",
    "mail",
    "fileshare",
    "dns",
)


def _config(*enabled: str) -> AptlConfig:
    """Build a config that enables exactly the named container profiles."""
    flags = {name: (name in enabled) for name in _CONTAINER_FIELDS}
    return AptlConfig(lab={"name": "techvault"}, containers=flags)


@dataclass(frozen=True)
class _Variant:
    catalog_id: str
    filename: str
    config: AptlConfig
    # Content-derived realization profiles (otel is the always-on core profile).
    expected_profiles: frozenset[str]

    @property
    def path(self) -> Path:
        return SCENARIOS_DIR / self.filename


VARIANTS = (
    _Variant(
        catalog_id="techvault-observability-core",
        filename="techvault-observability-core.sdl.yaml",
        config=_config(),
        expected_profiles=frozenset({"otel"}),
    ),
    _Variant(
        catalog_id="techvault-enterprise-web",
        filename="techvault-enterprise-web.sdl.yaml",
        config=_config("enterprise"),
        expected_profiles=frozenset({"enterprise", "otel"}),
    ),
    _Variant(
        catalog_id="techvault-defensive-min",
        filename="techvault-defensive-min.sdl.yaml",
        config=_config("wazuh"),
        expected_profiles=frozenset({"wazuh", "otel"}),
    ),
    _Variant(
        catalog_id="techvault-attacker-target",
        filename="techvault-attacker-target.sdl.yaml",
        config=_config("kali", "victim", "wazuh"),
        expected_profiles=frozenset({"kali", "victim", "wazuh", "otel"}),
    ),
)

VARIANTS_BY_ID = {variant.catalog_id: variant for variant in VARIANTS}


def _realization_details(variant: _Variant):
    scenario, parse_check = check_parse(variant.path)
    assert scenario is not None, f"{variant.filename} did not parse"
    assert parse_check.passed, parse_check.diagnostics
    details, check = check_provisioning_realization(
        scenario=scenario, project_dir=PROJECT_ROOT, config=variant.config
    )
    return details, check


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.catalog_id)
def test_variant_realizes_clean_with_expected_profiles(variant: _Variant):
    details, check = _realization_details(variant)

    # Parses, compiles, realizes with no error-severity APTL diagnostics, and
    # produces nodes/services/networks (all folded into check.passed).
    assert check.passed, check.diagnostics
    assert details is not None

    # Content-derived profile set is exactly the bounded slice we declared.
    assert frozenset(details.get("profiles", [])) == variant.expected_profiles

    # The selected Compose profile set for this scenario equals the public-start
    # set for a config that enables exactly the variant's profiles.
    selected = select_backend_profiles(
        variant.config, frozenset(details.get("profiles", []))
    )
    assert set(selected) == set(public_start_profiles(variant.config))


def test_variants_yield_distinct_realizations():
    """Anti-collapse: different declared content must not collapse to one set."""
    profile_sets = []
    for variant in VARIANTS:
        details, check = _realization_details(variant)
        assert check.passed, check.diagnostics
        profile_sets.append(frozenset(details.get("profiles", [])))
    assert len(set(profile_sets)) == len(VARIANTS)


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.catalog_id)
def test_variant_selection_is_content_driven_not_name_driven(variant: _Variant):
    """Renaming the scenario must not change the realized profile set."""
    text = variant.path.read_text(encoding="utf-8")
    original = parse_sdl(text)
    renamed = parse_sdl(text.replace("name: " + _scenario_name(text), "name: renamed-x", 1))

    original_details, original_check = check_provisioning_realization(
        scenario=original, project_dir=PROJECT_ROOT, config=variant.config
    )
    renamed_details, renamed_check = check_provisioning_realization(
        scenario=renamed, project_dir=PROJECT_ROOT, config=variant.config
    )

    assert original_check.passed and renamed_check.passed
    assert original_details.get("profiles") == renamed_details.get("profiles")
    assert frozenset(original_details.get("profiles", [])) == variant.expected_profiles


def _scenario_name(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("name:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError("scenario text has no top-level name")


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.catalog_id)
def test_variant_is_registered_and_resolvable(variant: _Variant):
    catalog = load_scenario_catalog(PROJECT_ROOT)
    ids = {entry.id for entry in catalog.scenarios}
    assert variant.catalog_id in ids

    resolved = resolve_scenario_selection(PROJECT_ROOT, scenario_id=variant.catalog_id)
    assert resolved == variant.path


def test_catalog_default_and_operational_scenario_unchanged():
    """The default public startup contract must remain techvault-operational."""
    catalog = load_scenario_catalog(PROJECT_ROOT)
    ids = [entry.id for entry in catalog.scenarios]
    assert ids[0] == "techvault-operational"
    assert set(VARIANTS_BY_ID).issubset(set(ids))
    assert DEFAULT_ACES_SCENARIO == Path("scenarios") / "techvault-operational.sdl.yaml"
