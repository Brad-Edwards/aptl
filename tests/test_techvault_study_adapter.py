"""Exact adapter admission for the separately identified TechVault study pack."""

from importlib import metadata
from pathlib import Path

from aptl.backends.scenario_runtime_parameters import resolve_runtime_parameters
from aptl.core.scenario_bundle import PackIdentity, ScenarioBundle, ScenarioSourceKind
from aptl_techvault.runtime_parameters import STUDY_PACK_SET_DIGEST
from aptl_techvault.study import PACK_ID, PACK_VERSION


def _bundle(digest: str) -> ScenarioBundle:
    return ScenarioBundle(
        identity=PACK_ID,
        root=Path("/unused"),
        sdl_path=Path("/unused/study.sdl.yaml"),
        source_kind=ScenarioSourceKind.ENV_PACK,
        pack_identity=PackIdentity(PACK_ID, PACK_VERSION, digest),
    )


def test_study_pack_has_exact_installed_adapter_claims() -> None:
    groups = (
        "aptl.pack_backend_interactions",
        "aptl.scenario_capture",
        "aptl.scenario_planning_compatibility",
        "aptl.scenario_runtime_parameters",
        "aptl.scenario_startup",
        "aptl.scenario_verifiers",
    )
    for group in groups:
        selector = PACK_ID if group in {
            "aptl.scenario_runtime_parameters",
            "aptl.scenario_startup",
        } else f"{PACK_ID}.aptl"
        (entry,) = [
            item for item in metadata.entry_points(group=group)
            if item.name == selector
        ]
        provider = entry.load()
        if group == "aptl.scenario_verifiers":
            assert {target.scenario.content_digest for target in provider.qualified_targets} == {
                STUDY_PACK_SET_DIGEST
            }
        else:
            assert provider.supported_pack_id == PACK_ID
            assert provider.supported_pack_set_digests == (STUDY_PACK_SET_DIGEST,)


def test_study_runtime_parameters_reject_other_digest() -> None:
    parameters = resolve_runtime_parameters(_bundle(STUDY_PACK_SET_DIGEST))
    assert parameters is not None
    assert len(parameters) == 10
    assert resolve_runtime_parameters(_bundle("sha256:" + "0" * 64)) is None
