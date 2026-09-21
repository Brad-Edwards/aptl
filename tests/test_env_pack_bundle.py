"""Released-pack compatibility: APTL admits the TechVault pack it ships against.

Content #875: APTL realizes TechVault from the ``raes-env-packs`` pack, not its
own checkout. The env-pack ships inside the installed ``raes_env_packs``
package; APTL's job (its side of the ADR-046 seam) is *trusted source
acquisition*: locate the bundled pack, stage an immutable owned copy, and refuse
to use it unless env-packs' own ``validate_pack`` /
``validate_pack_content_manifest`` gates pass.

These cases pin the *released* pack: its exact content identity, the evidence
contracts it still owns, and the configured default selection that resolves it.
The generic resolver behaviour -- staging isolation, singly-linked members,
containment, bytecode exclusion and fail-closed admission -- is proven against
APTL's owned fixture pack in ``tests/test_scenario_bundle.py`` (issue #985), so a
pack release cannot break it. The ``pack-identity-compatibility`` CI job runs
this module.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aptl.core.scenario_bundle import (
    EnvPackError,
    PackIdentity,
    ScenarioSourceKind,
    env_pack_bundle,
)

pytestmark = pytest.mark.integration


def test_directory_and_bundled_acquisition_preserve_the_same_identity(tmp_path):
    bundled = env_pack_bundle(tmp_path / "bundled")
    acquired = env_pack_bundle(tmp_path / "acquired", source_pack=bundled.root)
    assert acquired.pack_identity == bundled.pack_identity
    assert acquired.sdl_path.read_bytes() == bundled.sdl_path.read_bytes()
    assert acquired.root != bundled.root


@pytest.mark.parametrize("linked", ["pack.yaml", "sdl"])
def test_acquisition_rejects_source_links_before_copying(tmp_path, linked):
    source = env_pack_bundle(tmp_path / "source").root
    original = source / linked
    outside = tmp_path / ("outside-" + linked)
    original.rename(outside)
    original.symlink_to(outside, target_is_directory=outside.is_dir())
    with pytest.raises(EnvPackError, match="unsafe source"):
        env_pack_bundle(tmp_path / "destination", source_pack=source)


def test_new_acquisition_does_not_delete_long_running_input(tmp_path):
    import time

    root = tmp_path / "staged"
    active = env_pack_bundle(root)
    old = time.time() - 7200
    os.utime(active.root.parent, (old, old))
    env_pack_bundle(root)
    assert active.sdl_path.is_file()
    assert active.read_asset("pack.yaml")


@pytest.mark.parametrize("identity", ["../escape", "/tmp/escape", "a/b", ".", ".."])
def test_direct_acquisition_rejects_path_like_identity(tmp_path, identity):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(EnvPackError, match="identity"):
        env_pack_bundle(tmp_path / "staged", identity, source_pack=source)


def test_released_pack_owns_only_scenario_and_retains_its_evidence_contracts(
    tmp_path,
):
    from importlib.metadata import version
    from raes import parse_sdl
    from raes_processor.capture_admission import compile_scenario_capture_demands

    assert version("raes-env-packs") == "6.1.0"
    assert version("raes") == "5.0.0"
    bundle = env_pack_bundle(tmp_path / "released", "techvault")
    scenario = parse_sdl(bundle.sdl_path.read_text())
    assert not {"aptl-otel-collector", "aptl-tempo", "aptl-grafana-otel"}.intersection(
        scenario.nodes
    )
    assert set(scenario.evidence_requirements) == {
        "cortex-enrichment-readback",
        "misp-authenticated-api-readiness",
        "suricata-local-rule-readiness",
        "suricata-login-sqli-alert",
        "redteam-session-transcript",
        "wazuh-agent-readiness",
    }
    transcript = scenario.evidence_requirements["redteam-session-transcript"]
    assert transcript.integrity == "chain_of_custody"
    assert transcript.scope_refs == ["nodes.kali"]
    assert transcript.window == "the full run, from range readiness through teardown"
    assert all(
        intent.loss_disclosure == "required"
        for intent in scenario.evidence_requirements.values()
    )
    # Intent-only SDL requirements are executable demand in the released RAES
    # boundary; they do not need backend-invented capture-spec references.
    assert {
        demand.demand_id for demand in compile_scenario_capture_demands(scenario)
    } == set(scenario.evidence_requirements)


def test_env_pack_bundle_stages_and_validates_the_bundled_techvault_pack(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "staged-packs"
    bundle = env_pack_bundle(staging, "techvault")

    assert bundle.source_kind is ScenarioSourceKind.ENV_PACK
    assert bundle.identity == "techvault"
    assert bundle.pack_identity == PackIdentity(
        pack_id="techvault",
        pack_version="0.1.0",
        set_digest=(
            "sha256:db98a9daa62a092a0c6b001217027d7f4ad489889e95d01050e77f148e8ef29b"
        ),
    )
    # The bundle roots at the staged copy, never at the installed package.
    assert staging in bundle.root.parents or bundle.root.parent == staging
    assert bundle.sdl_path == bundle.root / "sdl" / "techvault.sdl.yaml"
    assert bundle.sdl_path.is_file()
    assert (bundle.root / "pack.yaml").is_file()
    assert (bundle.root / "associated-artifacts.json").is_file()


def test_scenario_selection_resolves_the_env_pack_when_configured(
    tmp_path: Path,
) -> None:
    # config.scenario.source == "env-pack" selects the staged pack (default
    # selection, no explicit --scenario-path override).
    from aptl.backends.raes import resolve_scenario_bundle
    from aptl.core.config import AptlConfig

    config = AptlConfig(scenario={"identity": "techvault", "source": "env-pack"})
    bundle = resolve_scenario_bundle(tmp_path, None, config)
    assert bundle.source_kind is ScenarioSourceKind.ENV_PACK
    assert bundle.identity == "techvault"
    assert bundle.sdl_path.is_file()
    # An explicit path overrides the pack (operator override stays project-tree).
    local = tmp_path / "scenarios" / "custom.sdl.yaml"
    override = resolve_scenario_bundle(tmp_path, local, config)
    assert override.source_kind is ScenarioSourceKind.PROJECT_TREE
