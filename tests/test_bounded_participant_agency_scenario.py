"""Static gates for the selected bounded-participant-agency semantic input."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from raes import parse_sdl_file
from raes.instantiate import instantiate_scenario
from raes_backend_protocols.participant_runtime_base import BaseParticipantRuntime
from raes_processor.compiler import compile_runtime_model
from raes_contracts.runtime_state import OperationState
from raes_runtime.control_plane import RuntimeControlPlane

from aptl.backends.raes import _plan_scenario, create_aptl_runtime_target
from aptl.backends.raes_realization import interpret_provisioning_plan
from aptl.backends.raes_participant_actions import PARTICIPANT_ACTION_ADDRESS
from aptl.backends.raes_runtime_model_artifact import compiled_runtime_model_bytes
from aptl.backends.raes_participant_runtime import AptlParticipantRuntime
from aptl.backends.raes_participant_realizations import (
    BPA_ACTION_REALIZATIONS,
    ParticipantRealizationReadinessError,
    validate_participant_realizations,
)
from aptl.core.config import AptlConfig
from aptl.core.scenario_bundle import ScenarioBundle, project_tree_bundle

PROJECT_ROOT = Path(__file__).parents[1]
SCENARIO = PROJECT_ROOT / "scenarios/bounded-participant-agency-techvault.sdl.yaml"
SOURCE_SHA256 = "9683f2539bdefbd99635924d2a6fce27b144e12f382cd74d2f3e10d10ecb7616"
COMPILED_SHA256 = "7a29b45d3949ccf083ea048261421096ab81d94b4524a3ac37426a8ed09998f7"


def _bundle() -> ScenarioBundle:
    """The in-tree bundle for the frozen research scenario (issue #874).

    Rooted at the project directory these calls previously passed as
    ``project_dir``, so realization is unchanged.
    """
    return project_tree_bundle(PROJECT_ROOT, SCENARIO)


def test_selected_scenario_is_the_exact_research_freeze() -> None:
    assert hashlib.sha256(SCENARIO.read_bytes()).hexdigest() == SOURCE_SHA256


def test_selected_scenario_compiles_the_complete_participant_surface() -> None:
    scenario = parse_sdl_file(SCENARIO)
    model = compile_runtime_model(instantiate_scenario(scenario, {}))

    assert len(model.participant_behaviors) == 3
    assert len(model.behavior_specifications) == 9
    assert len(model.observation_boundaries) == 9
    assert len(model.action_contracts) == 26


@dataclass(frozen=True)
class _CanonicalModelProbe:
    values: dict[str, int]


def test_compiled_model_artifact_is_versioned_and_order_independent() -> None:
    first = compiled_runtime_model_bytes(
        _CanonicalModelProbe(values={"beta": 2, "alpha": 1})
    )
    second = compiled_runtime_model_bytes(
        _CanonicalModelProbe(values={"alpha": 1, "beta": 2})
    )

    assert first == second
    assert json.loads(first)["schema"] == ("aptl.raes-runtime-model-artifact/v1")


def test_compiled_model_artifact_rejects_lossy_string_coercion() -> None:
    with pytest.raises(TypeError, match="unsupported canonical value"):
        compiled_runtime_model_bytes(object())


def test_selected_scenario_has_no_blocking_backend_diagnostics() -> None:
    config = AptlConfig(lab={"name": "test"})
    _, plan = _plan_scenario(
        PROJECT_ROOT,
        config,
        MagicMock(),
        SCENARIO,
        None,
    )

    assert [diagnostic for diagnostic in plan.diagnostics if diagnostic.is_error] == []
    realization = interpret_provisioning_plan(
        plan=plan.provisioning,
        config=config,
        bundle=_bundle(),
    )
    assert [
        diagnostic for diagnostic in realization.diagnostics if diagnostic.is_error
    ] == []
    content_placements = [
        placement
        for placement in realization.placements
        if placement.resource_type == "content-placement"
    ]
    assert len(content_placements) == len(plan.model.content_placements)
    assert all(
        placement.content is not None or placement.dataset is not None
        for placement in content_placements
    )
    assert {
        placement.dataset.storage_kind
        for placement in content_placements
        if placement.dataset is not None
    } == {"aptl-participant-run-store-jsonl"}
    containers = {node.name: node.container_name for node in realization.nodes}
    assert containers["defender-console"] == "aptl-defender-console"
    assert containers["event-store"] == "aptl-event-store"


def test_aptl_runtime_uses_raes_owned_participant_lifecycle() -> None:
    assert issubclass(AptlParticipantRuntime, BaseParticipantRuntime)


def test_backend_manifest_truthfully_declares_the_research_surface() -> None:
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT,
        config=AptlConfig(lab={"name": "test"}),
        backend=MagicMock(),
        bundle=_bundle(),
    )
    capability = target.manifest.participant_runtime
    assert capability is not None
    assert capability.supported_participant_roles == frozenset({"green", "red", "blue"})
    assert {"action_contracts", "observation_boundaries", "behavior_history"} <= set(
        capability.supported_behavior_features
    )


def test_aptl_has_one_closed_realization_for_every_compiled_action() -> None:
    scenario = parse_sdl_file(SCENARIO)
    model = compile_runtime_model(instantiate_scenario(scenario, {}))
    realization = {
        "nodes": [
            {"name": name, "container_name": f"aptl-{name}"}
            for name in (
                "webapp",
                "db",
                "workstation",
                "kali",
                "defender-console",
                "event-store",
            )
        ]
    }

    readiness = validate_participant_realizations(
        model,
        realization,
        registry=BPA_ACTION_REALIZATIONS,
    )

    assert set(readiness.action_contract_addresses) == set(model.action_contracts)
    assert dict(readiness.target_containers) == {
        name: f"aptl-{name}"
        for name in (
            "webapp",
            "db",
            "kali",
            "defender-console",
            "event-store",
        )
    }


def test_participant_realization_readiness_fails_closed_on_missing_handler() -> None:
    scenario = parse_sdl_file(SCENARIO)
    model = compile_runtime_model(instantiate_scenario(scenario, {}))
    incomplete = dict(BPA_ACTION_REALIZATIONS)
    incomplete.pop("participant.action-contract.inspect-portal")

    try:
        validate_participant_realizations(model, {"nodes": []}, registry=incomplete)
    except ParticipantRealizationReadinessError as exc:
        assert "participant.action-contract.inspect-portal" in str(exc)
    else:
        raise AssertionError("missing participant action realization was accepted")


def test_final_runtime_target_retains_the_exact_admitted_plan_and_model() -> None:
    target, plan = _plan_scenario(
        PROJECT_ROOT,
        AptlConfig(lab={"name": "test"}),
        MagicMock(),
        SCENARIO,
        None,
    )

    authority = target.participant_runtime.plan_authority
    assert authority is not None
    assert authority.execution_plan is plan
    assert authority.runtime_model is plan.model
    assert authority.scenario_source_sha256 == SOURCE_SHA256
    assert authority.compiled_model_sha256 == COMPILED_SHA256


def test_privileged_realization_rejects_same_name_with_unapproved_source(
    tmp_path: Path,
) -> None:
    modified = tmp_path / SCENARIO.name
    modified.write_bytes(SCENARIO.read_bytes() + b"\n")
    target, _ = _plan_scenario(
        PROJECT_ROOT,
        AptlConfig(lab={"name": "test"}),
        MagicMock(),
        modified,
        None,
    )
    authority = target.participant_runtime.plan_authority
    assert authority is not None
    assert authority.is_bounded_participant_agency is True
    assert authority.is_approved_bounded_participant_agency is False

    try:
        authority.bind_runtime_context(
            {
                "nodes": [
                    {"name": name, "container_name": f"aptl-{name}"}
                    for name in (
                        "webapp",
                        "db",
                        "workstation",
                        "kali",
                        "defender-console",
                        "event-store",
                    )
                ]
            },
            run_store=None,
            run_id=None,
        )
    except ValueError as exc:
        assert "approved authored and compiled scenario identities" in str(exc)
    else:
        raise AssertionError("unapproved same-name scenario reached the registry")


def test_episode_initialization_is_lifecycle_only() -> None:
    backend = MagicMock()
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT,
        config=AptlConfig(lab={"name": "test"}),
        backend=backend,
        bundle=_bundle(),
    )
    control_plane = RuntimeControlPlane(target)

    receipt = control_plane.initialize_participant_episode(PARTICIPANT_ACTION_ADDRESS)

    status = control_plane.get_operation(receipt.operation_id)
    assert status is not None
    assert status.state == OperationState.SUCCEEDED
    backend.container_exec.assert_not_called()
    assert control_plane.snapshot.participant_behavior_history == {}
