"""Realization-engine coverage driven by a test-owned SDL fixture.

No product catalog scenario exercises `evidence_requirements`, the
`x-aptl:participant-runtime-binding` behavior-spec governed extension,
observation boundaries, action contracts, or outcome-interpretation rules.
These tests drive `tests/fixtures/aces/participant-evidence.sdl.yaml` — test
data that lives with the tests and is intentionally absent from
`scenarios/catalog.json` — so realization-engine coverage never depends on a
shipped scenario.
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aces_contracts.runtime_state import OperationState
from aces_processor.compiler import compile_runtime_model
from aces_runtime.control_plane import RuntimeControlPlane
from aces_runtime.manager import RuntimeManager
from aces_sdl import parse_sdl_file

from aptl.backends.aces import create_aptl_runtime_target
from aptl.backends.aces_participant_actions import (
    DEFAULT_PARTICIPANT_ACTIONS,
    _action_snapshot_entries,
    participant_action_specs_from_runtime_model,
)
from aptl.backends.aces_participant_bindings import (
    _BINDING_EXTENSION_KEY,
    _BINDING_SCHEMA,
    _assert_compiled_addresses,
)
from aptl.backends.aces_profiles import select_backend_profiles
from aptl.backends.aces_realization import interpret_provisioning_plan
from aptl.core.config import AptlConfig
from aptl.core.deployment.realization import DeploymentContentRealization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    PROJECT_ROOT / "tests" / "fixtures" / "aces" / "participant-evidence.sdl.yaml"
)

PARTICIPANT_ADDRESS = "participant.behavior.probe-agent"
BEHAVIOR_SPEC_ADDRESS = "participant.behavior-specification.probe-agent-behavior"
ACTION_CONTRACT_ADDRESS = "participant.action-contract.probe-customer-portal-login"
OBSERVATION_BOUNDARY_ADDRESS = "participant.observation-boundary.probe-agent-view"


def _config():
    return AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "kali": True, "wazuh": True},
    )


def _compile_model_plan_config():
    scenario = parse_sdl_file(FIXTURE)
    model = compile_runtime_model(scenario)
    config = _config()
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT, config=config, backend=MagicMock()
    )
    return scenario, model, RuntimeManager(target).plan(scenario), config


def _binding(model):
    spec = model.behavior_specifications[BEHAVIOR_SPEC_ADDRESS].spec
    return spec["extensions"][_BINDING_EXTENSION_KEY]


def test_fixture_compiles_with_participant_runtime_artifacts():
    scenario, model, _plan, _config = _compile_model_plan_config()

    assert model.diagnostics == []
    # The runtime binding rides the behavior-spec governed extension, not content.
    assert (
        "provision.content.aptl-participant-runtime-binding"
        not in model.content_placements
    )
    binding = _binding(model)
    assert binding["schema_version"] == _BINDING_SCHEMA
    assert binding["command"]["argv"][:2] == ["bash", "-lc"]

    # Evidence surfaces are authored ACES evidence requirements, not content.
    assert set(scenario.evidence_requirements) == {
        "wazuh-evidence",
        "boundary-check-evidence",
    }
    assert set(scenario.content) == {"task-brief"}
    assert PARTICIPANT_ADDRESS in model.participant_behaviors
    assert ACTION_CONTRACT_ADDRESS in model.action_contracts
    assert OBSERVATION_BOUNDARY_ADDRESS in model.observation_boundaries


def test_fixture_content_surface_realizes_with_no_rejection():
    _scenario, _model, plan, config = _compile_model_plan_config()

    realization = interpret_provisioning_plan(
        plan=plan.provisioning, project_dir=PROJECT_ROOT, config=config
    )
    assert [
        d
        for d in realization.diagnostics
        if d.code == "aptl.provisioner.content-placement-rejected"
    ] == []
    assert realization.diagnostics == ()

    content_placements = [
        placement
        for placement in realization.placements
        if placement.resource_type == "content-placement"
    ]
    assert [p.address for p in content_placements] == ["provision.content.task-brief"]
    task_brief = content_placements[0].content
    assert isinstance(task_brief, DeploymentContentRealization)
    assert task_brief.content_name == "task-brief"
    assert task_brief.volume_suffix == "kali_operations"
    assert task_brief.dest_relpath == "scenario/task.md"
    assert task_brief.source_kind == "inline-text"
    assert select_backend_profiles(config, realization.profiles) == [
        "wazuh",
        "kali",
        "enterprise",
        "otel",
    ]


def test_fixture_evidence_requirements_declare_authored_capture_intent():
    scenario, _model, _plan, _config = _compile_model_plan_config()

    wazuh = scenario.evidence_requirements["wazuh-evidence"]
    assert wazuh.source_class.value == "scenario_native_observability"
    assert wazuh.scope_refs == ["nodes.wazuh-manager"]
    assert wazuh.trigger_ref == "action_contracts.probe-customer-portal-login"

    boundary = scenario.evidence_requirements["boundary-check-evidence"]
    assert boundary.source_class.value == "participant_action"
    assert boundary.scope_refs == ["nodes.red-workbench"]
    assert boundary.boundary_ref == "observation_boundaries.probe-agent-view"


def test_fixture_observation_boundary_hides_evaluator_and_negative_surfaces():
    _scenario, model, plan, config = _compile_model_plan_config()

    specs = participant_action_specs_from_runtime_model(
        model,
        provisioning_plan=plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
    )
    spec = specs[PARTICIPANT_ADDRESS]
    entries = _action_snapshot_entries(
        PARTICIPANT_ADDRESS, spec, "probe-0001", success=True
    )
    boundary = entries[spec.observation_boundary_address].payload

    # ADR-046: internal DB / Wazuh endpoint identities (the negative-boundary
    # refs) must never project into the participant view.
    projected = set(boundary["observable_refs"]) | set(boundary["disclosed_refs"])
    assert not any(ref.startswith("boundary-negative:") for ref in projected)
    assert boundary["observable_refs"] == [
        "container:aptl-kali",
        "container:aptl-webapp",
        "http://172.20.1.20:8080/login",
    ]
    # They remain as evaluator-only evidence alongside the action instance.
    assert boundary["evidence_refs"] == [
        "probe-0001",
        "boundary-negative:tcp:172.20.2.11:5432",
        "boundary-negative:tcp:172.20.2.30:55000",
    ]


def test_participant_action_uses_compiled_addresses_and_boundary_markers(tmp_path):
    assert PARTICIPANT_ADDRESS not in DEFAULT_PARTICIPANT_ACTIONS
    assert not (
        PROJECT_ROOT / "src/aptl/backends/aces_paper_participant_actions.py"
    ).exists()

    backend = MagicMock()
    backend.container_exec.return_value = subprocess.CompletedProcess(
        args=["bash"],
        returncode=0,
        stdout=(
            "portal_http_status=200\n"
            "boundary_db=blocked\n"
            "boundary_wazuh_api=blocked\n"
        ),
        stderr="",
    )
    _scenario, model, plan, config = _compile_model_plan_config()
    participant_action_specs = participant_action_specs_from_runtime_model(
        model,
        provisioning_plan=plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
    )
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
        participant_action_specs=participant_action_specs,
    )
    control_plane = RuntimeControlPlane(target)

    receipt = control_plane.initialize_participant_episode(PARTICIPANT_ADDRESS)
    status = control_plane.get_operation(receipt.operation_id)

    assert status is not None
    assert status.state == OperationState.SUCCEEDED, status.diagnostics
    backend.container_exec.assert_called_once()
    container_name, command = backend.container_exec.call_args.args
    assert container_name == "aptl-kali"
    assert command[:2] == ["bash", "-lc"]
    assert "172.20.1.20:8080/login" in command[2]
    assert "172.20.2.11/5432" in command[2]
    assert "172.20.2.30/55000" in command[2]
    behavior = control_plane.snapshot.participant_behavior_history[PARTICIPANT_ADDRESS]
    assert behavior[0]["action_contract_address"] == ACTION_CONTRACT_ADDRESS
    assert behavior[-1]["observation_boundary_address"] == OBSERVATION_BOUNDARY_ADDRESS
    assert "boundary_db=blocked" in behavior[-1]["details"]["stdout_excerpt"]
    entries = control_plane.snapshot.entries
    assert (
        entries[PARTICIPANT_ADDRESS].payload["participant_address"]
        == PARTICIPANT_ADDRESS
    )
    assert entries[ACTION_CONTRACT_ADDRESS].payload["action_name"] == (
        "probe-customer-portal-login"
    )
    assert entries[OBSERVATION_BOUNDARY_ADDRESS].payload["boundary_name"] == (
        "probe-agent-view"
    )
    # The fixture participant must not reuse the legacy TechVault SSH identifiers.
    assert "Kali victim SSH" not in str(entries[ACTION_CONTRACT_ADDRESS].payload)
    assert "kali-victim-ssh" not in str(entries[OBSERVATION_BOUNDARY_ADDRESS].payload)
    shared_state_records = getattr(
        control_plane.snapshot, "shared_state_records", {}
    )
    assert {
        record["state_scope"] for record in shared_state_records.values()
    } == {PARTICIPANT_ADDRESS}
    assert participant_action_specs[PARTICIPANT_ADDRESS].target_refs == (
        "container:aptl-kali",
        "container:aptl-webapp",
        "http://172.20.1.20:8080/login",
        "boundary-negative:tcp:172.20.2.11:5432",
        "boundary-negative:tcp:172.20.2.30:55000",
    )


def test_runtime_model_without_participant_artifacts_registers_no_action():
    class EmptyModel:
        participant_behaviors = {}
        action_contracts = {}
        observation_boundaries = {}
        behavior_specifications = {}
        content_placements = {}

    _scenario, _model, plan, config = _compile_model_plan_config()

    assert (
        participant_action_specs_from_runtime_model(
            EmptyModel(),
            provisioning_plan=plan.provisioning,
            project_dir=PROJECT_ROOT,
            config=config,
        )
        == {}
    )


def test_valid_binding_yields_participant_spec_baseline():
    """Baseline for the fail-closed cases: the untouched binding produces a spec."""
    _scenario, model, plan, config = _compile_model_plan_config()
    specs = participant_action_specs_from_runtime_model(
        model,
        provisioning_plan=plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
    )
    assert PARTICIPANT_ADDRESS in specs


def _set_runtime_target(binding):
    binding["runtime_target"] = "libvirt"


def _set_unknown_action(binding):
    binding["action_contract_ref"] = "no-such-action"


def _set_unknown_boundary(binding):
    binding["observation_boundary_ref"] = "no-such-boundary"


def _add_unresolvable_target_ref(binding):
    binding["target_refs"].append("container:{{ container:nodes.ghost-node }}")


def _empty_argv(binding):
    binding["command"]["argv"] = []


def _empty_success_markers(binding):
    binding["success_markers"] = []


@pytest.mark.parametrize(
    "mutate",
    [
        _set_runtime_target,
        _set_unknown_action,
        _set_unknown_boundary,
        _add_unresolvable_target_ref,
        _empty_argv,
        _empty_success_markers,
    ],
    ids=[
        "non-aptl-runtime-target",
        "uncompiled-action-contract",
        "uncompiled-observation-boundary",
        "unresolvable-template-placeholder",
        "empty-argv",
        "empty-success-markers",
    ],
)
def test_malformed_binding_is_dropped_fail_closed(mutate):
    """A semantically invalid binding fails closed — the spec is dropped (#691).

    ``participant_action_specs_from_runtime_model`` swallows the per-binding
    ``TypeError`` / ``ValueError`` from ``_spec_from_binding`` /
    ``_assert_compiled_addresses`` / ``_render_template`` and simply omits the
    action. Without these cases every fail-closed check could silently regress
    (raise the wrong type, or stop raising) while the one valid fixture test
    still passed.
    """
    _scenario, model, plan, config = _compile_model_plan_config()
    mutate(_binding(model))

    specs = participant_action_specs_from_runtime_model(
        model,
        provisioning_plan=plan.provisioning,
        project_dir=PROJECT_ROOT,
        config=config,
    )
    assert PARTICIPANT_ADDRESS not in specs


def test_assert_compiled_addresses_rejects_compiled_but_unassigned_refs():
    """Refs that are compiled but not assigned to the participant fail closed.

    Complements the end-to-end fail-closed cases: those hit the "uncompiled
    artifact" branch, this pins the two "compiled but not assigned to this
    participant" branches that a single-action fixture cannot reach.
    """
    from types import SimpleNamespace

    behavior = SimpleNamespace(
        action_contract_addresses=("participant.action-contract.assigned",),
        observation_boundary_addresses=(
            "participant.observation-boundary.assigned",
        ),
    )
    model = SimpleNamespace(
        participant_behaviors={"p": behavior},
        action_contracts={
            "participant.action-contract.assigned": object(),
            "participant.action-contract.other": object(),
        },
        observation_boundaries={
            "participant.observation-boundary.assigned": object(),
            "participant.observation-boundary.other": object(),
        },
    )

    with pytest.raises(ValueError, match="action contract is not assigned"):
        _assert_compiled_addresses(
            model,
            "p",
            "participant.action-contract.other",
            "participant.observation-boundary.assigned",
        )
    with pytest.raises(ValueError, match="observation boundary is not assigned"):
        _assert_compiled_addresses(
            model,
            "p",
            "participant.action-contract.assigned",
            "participant.observation-boundary.other",
        )
    with pytest.raises(ValueError, match="uncompiled participant artifacts"):
        _assert_compiled_addresses(
            model,
            "p",
            "participant.action-contract.ghost",
            "participant.observation-boundary.assigned",
        )
    with pytest.raises(ValueError, match="uncompiled participant artifacts"):
        _assert_compiled_addresses(
            model,
            "missing-participant",
            "participant.action-contract.assigned",
            "participant.observation-boundary.assigned",
        )
