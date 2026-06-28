"""Tests for the APTL ACES runtime handoff."""

from pathlib import Path
from unittest.mock import MagicMock

from aces_contracts.planning import (
    ChangeAction,
    EvaluationPlan,
    OrchestrationPlan,
    PlannedResource,
    ProvisioningPlan,
    ProvisionOp,
    RuntimeDomain,
)
from aces_contracts.runtime_state import RuntimeSnapshot

from aptl.core.config import AptlConfig
from aptl.core.lab_types import LabResult


def _write_compose(project_dir: Path, services: dict[str, list[str]]) -> None:
    lines = ["services:"]
    for service_name, profiles in services.items():
        rendered = ", ".join(f'"{profile}"' for profile in profiles)
        lines.extend(
            [
                f"  {service_name}:",
                f"    profiles: [{rendered}]",
                "    image: example:latest",
            ]
        )
    (project_dir / "docker-compose.yml").write_text("\n".join(lines))


def _write_compose_graph(
    project_dir: Path,
    services: dict[str, tuple[list[str], list[str]]],
    networks: dict[str, list[str]] | None = None,
) -> None:
    lines = ["services:"]
    for service_name, (profiles, dependencies) in services.items():
        rendered = ", ".join(f'"{profile}"' for profile in profiles)
        lines.extend(
            [
                f"  {service_name}:",
                f"    profiles: [{rendered}]",
                "    image: example:latest",
            ]
        )
        if dependencies:
            lines.append("    depends_on:")
            for dependency in dependencies:
                lines.extend(
                    [f"      {dependency}:", "        condition: service_started"]
                )
        service_networks = (networks or {}).get(service_name, [])
        if service_networks:
            lines.append("    networks:")
            for network in service_networks:
                lines.append(f"      - {network}")
    (project_dir / "docker-compose.yml").write_text("\n".join(lines))


def _node_resource(node_name: str) -> PlannedResource:
    address = f"provision.node.{node_name}"
    payload = {
        "name": node_name,
        "node_name": node_name,
        "node_type": "vm",
        "os_family": "linux",
        "spec": {"node": {"name": node_name}, "infrastructure": {}},
    }
    return PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload=payload,
    )


def _node_resource_with_dependencies(
    node_name: str,
    *dependencies: str,
) -> PlannedResource:
    resource = _node_resource(node_name)
    resource.payload["spec"]["infrastructure"]["dependencies"] = list(dependencies)
    return resource


def _plan_for_resources(*resources: PlannedResource) -> ProvisioningPlan:
    mapped = {resource.address: resource for resource in resources}
    operations = [
        ProvisionOp(
            action=ChangeAction.CREATE,
            address=resource.address,
            resource_type=resource.resource_type,
            payload=resource.payload,
        )
        for resource in mapped.values()
    ]
    return ProvisioningPlan(resources=mapped, operations=operations)


def _plan_for_nodes(*node_names: str) -> ProvisioningPlan:
    return _plan_for_resources(*map(_node_resource, node_names))


def _plan_with_resource_type(resource_type: str) -> ProvisioningPlan:
    resource = PlannedResource(
        address=f"provision.{resource_type}.example",
        domain=RuntimeDomain.PROVISIONING,
        resource_type=resource_type,
        payload={"name": "example"},
    )
    return ProvisioningPlan(
        resources={resource.address: resource},
        operations=[
            ProvisionOp(
                action=ChangeAction.CREATE,
                address=resource.address,
                resource_type=resource.resource_type,
                payload=resource.payload,
            )
        ],
    )


def test_create_runtime_target_accepts_aptl_manifest_shape(tmp_path):
    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"})

    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )

    assert target.name == "aptl"
    assert target.manifest.name == "aptl"
    assert target.participant_runtime is not None


def test_public_start_profiles_match_start_lab_backend_call():
    from aptl.backends.aces_profiles import public_start_profiles
    from aptl.core.lab import start_lab

    backend = MagicMock()
    backend.start.return_value = LabResult(success=True)
    config = AptlConfig(
        lab={"name": "test"},
        containers={
            "wazuh": True,
            "victim": False,
            "kali": True,
            "reverse": False,
            "enterprise": True,
            "soc": False,
            "mail": False,
            "fileshare": True,
            "dns": False,
        },
    )

    result = start_lab(config, project_dir=Path("."), backend=backend)

    assert result.success is True
    backend.start.assert_called_once_with(public_start_profiles(config))


def test_realization_accepts_core_otel_as_public_start_profile(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"aptl-otel-collector": ["otel"]})
    config = AptlConfig(
        lab={"name": "test"},
        containers={
            "wazuh": False,
            "victim": False,
            "kali": False,
            "reverse": False,
            "enterprise": False,
            "soc": False,
            "mail": False,
            "fileshare": False,
            "dns": False,
        },
    )

    realization = interpret_provisioning_plan(
        plan=_plan_for_nodes("aptl-otel-collector"),
        project_dir=tmp_path,
        config=config,
    )

    assert realization.profiles == frozenset({"otel"})
    assert [diag.code for diag in realization.diagnostics] == []


class _FakeExecutionPlan:
    """Minimal ExecutionPlan stand-in exposing the fields the handoff reads."""

    def __init__(
        self,
        provisioning,
        *,
        is_valid=True,
        diagnostics=None,
        orchestration=None,
        evaluation=None,
    ):
        self.provisioning = provisioning
        self.orchestration = orchestration or OrchestrationPlan()
        self.evaluation = evaluation or EvaluationPlan()
        self.base_snapshot = RuntimeSnapshot()
        self.is_valid = is_valid
        self.diagnostics = diagnostics or []


def test_create_aptl_manifest_is_canonical_backend_manifest_v2():
    from aces_backend_protocols.capabilities import BackendManifest
    from aces_backend_protocols.manifest import backend_manifest_payload

    from aptl.backends.aces_manifest import create_aptl_manifest

    manifest = create_aptl_manifest()

    assert isinstance(manifest, BackendManifest)
    payload = backend_manifest_payload(manifest)
    assert payload["schema_version"] == "backend-manifest/v2"
    required = {
        "backend-manifest-v2",
        "provisioning-plan-v1",
        "orchestration-plan-v1",
        "evaluation-plan-v1",
        "operation-receipt-v1",
        "operation-status-v1",
        "runtime-snapshot-v1",
        "workflow-result-envelope-v1",
        "workflow-history-event-stream-v1",
        "evaluation-result-envelope-v1",
        "evaluation-history-event-stream-v1",
        "participant-episode-state-envelope-v1",
        "participant-episode-history-event-stream-v1",
        "participant-behavior-history-event-stream-v1",
    }
    assert required <= set(payload["supported_contract_versions"])
    assert manifest.has_orchestrator is True
    assert manifest.has_evaluator is True
    assert manifest.has_participant_runtime is True
    assert manifest.participant_runtime is not None
    assert manifest.participant_runtime.supported_participant_roles == frozenset(
        {"red"}
    )
    assert payload["capabilities"]["participant_runtime"] is not None


def test_aptl_target_passes_provisioning_only_conformance(tmp_path):
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )

    report = run_target_conformance(target, profile="provisioning-only")

    assert report.passed is True, [d.code for d in report.diagnostics]
    assert report.unsupported_contract_gaps == ()
    assert report.unsupported_capability_gaps == ()


def test_aptl_target_passes_orchestration_evaluation_conformance(tmp_path):
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )

    report = run_target_conformance(target, profile="orchestration-evaluation")

    assert report.passed is True, [d.code for d in report.diagnostics]
    assert report.unsupported_contract_gaps == ()
    assert report.unsupported_capability_gaps == ()
    assert all(case.passed for case in report.cases), [
        (case.name, [d.message for d in case.diagnostics])
        for case in report.cases
        if not case.passed
    ]


def test_aptl_target_passes_full_remote_control_plane_conformance(tmp_path):
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )

    report = run_target_conformance(target, profile="full-remote-control-plane")

    assert report.passed is True, [d.code for d in report.diagnostics]
    assert report.unsupported_contract_gaps == ()
    assert report.unsupported_capability_gaps == ()
    assert all(case.passed for case in report.cases), [
        (case.name, [d.message for d in case.diagnostics])
        for case in report.cases
        if not case.passed
    ]


def test_participant_runtime_lifecycle_updates_control_plane_snapshot(tmp_path):
    from aces_contracts.participant_episode import (
        ParticipantEpisodeTerminalReason,
        iter_participant_episode_snapshot_violations,
    )
    from aces_contracts.runtime_state import OperationState
    from aces_runtime.control_plane import RuntimeControlPlane

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )
    control_plane = RuntimeControlPlane(target)
    participant = "participant.conformance"

    init = control_plane.initialize_participant_episode(participant)
    reset = control_plane.reset_participant_episode(participant)
    terminate = control_plane.terminate_participant_episode(
        participant,
        terminal_reason=ParticipantEpisodeTerminalReason.COMPLETED,
    )
    restart = control_plane.restart_participant_episode(participant)

    for receipt in (init, reset, terminate, restart):
        status = control_plane.get_operation(receipt.operation_id)
        assert status is not None
        assert status.state == OperationState.SUCCEEDED, status.diagnostics

    snapshot = control_plane.snapshot
    assert participant in snapshot.participant_episode_results
    assert len(snapshot.participant_episode_history[participant]) >= 6
    assert (
        list(
            iter_participant_episode_snapshot_violations(
                snapshot.participant_episode_results,
                snapshot.participant_episode_history,
            )
        )
        == []
    )


def test_participant_runtime_action_drives_backend_and_records_behavior(tmp_path):
    import subprocess

    from aces_contracts.participant_behavior import (
        iter_participant_behavior_snapshot_violations,
    )
    from aces_contracts.runtime_state import OperationState
    from aces_runtime.control_plane import RuntimeControlPlane

    from aptl.backends.aces import create_aptl_runtime_target
    from aptl.backends.aces_participant_runtime import PARTICIPANT_ACTION_ADDRESS

    backend = MagicMock()
    backend.container_exec.return_value = subprocess.CompletedProcess(
        args=["nmap"],
        returncode=0,
        stdout="Host: 172.20.2.20 () Ports: 22/open/tcp//ssh///",
        stderr="",
    )
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
    )
    control_plane = RuntimeControlPlane(target)

    receipt = control_plane.initialize_participant_episode(PARTICIPANT_ACTION_ADDRESS)
    status = control_plane.get_operation(receipt.operation_id)

    assert status is not None
    assert status.state == OperationState.SUCCEEDED, status.diagnostics
    backend.container_exec.assert_called_once_with(
        "aptl-kali",
        ["nmap", "-p", "22", "-Pn", "--open", "172.20.2.20", "-oG", "-"],
        timeout=120,
    )
    snapshot = control_plane.snapshot
    behavior = snapshot.participant_behavior_history[PARTICIPANT_ACTION_ADDRESS]
    assert [event["event_type"] for event in behavior] == [
        "action_attempted",
        "observation_emitted",
    ]
    assert behavior[-1]["actor_provenance"] == "codex-cli"
    assert "22/open" in behavior[-1]["details"]["stdout_excerpt"]
    assert any(
        entry.resource_type == "participant-action-instance"
        for entry in snapshot.entries.values()
    )
    assert (
        list(
            iter_participant_behavior_snapshot_violations(
                snapshot.participant_behavior_history,
                participant_episode_results=snapshot.participant_episode_results,
                participant_episode_history=snapshot.participant_episode_history,
                metadata=snapshot.metadata,
            )
        )
        == []
    )


def _participant_admission_request(participant_address: str):
    """Build a valid ParticipantActionAdmissionRequest for *participant_address*.

    Mirrors the ACES participant implementation-binding contract shape (manifest
    + selection + addresses) so admit_action can be exercised end-to-end.
    """
    from aces_contracts.contracts import (
        ParticipantImplementationManifestModel,
        ParticipantImplementationSelectionModel,
    )
    from aces_contracts.participant_binding import ParticipantActionAdmissionRequest

    manifest = ParticipantImplementationManifestModel.model_validate(
        {
            "schema_version": "participant-implementation-manifest/v1",
            "identity": {"name": "aptl-admit-probe", "version": "1.0.0"},
            "implementation_kind": "agent",
            "supported_contract_versions": [
                "participant-implementation-manifest-v1",
                "participant-implementation-provenance-v1",
                "participant-episode-state-envelope-v1",
                "participant-behavior-history-event-stream-v1",
            ],
            "compatibility": {
                "participant_runtimes": ["aptl"],
                "processors": [],
                "backends": [],
            },
            "concept_bindings": [
                {"scope": "implementation_kind", "family": "apparatus-declarations"},
                {
                    "scope": "capabilities.supported_participant_contracts",
                    "family": "apparatus-declarations",
                },
                {
                    "scope": "capabilities.supported_decision_surface_modes",
                    "family": "apparatus-declarations",
                },
                {
                    "scope": "capabilities.tool_affordance_expectations",
                    "family": "tools-and-artifacts",
                },
                {
                    "scope": "capabilities.exposure_policy_kinds",
                    "family": "provenance-and-evidence",
                },
            ],
            "capabilities": {
                "supported_participant_contracts": [
                    "participant-episode-state-envelope-v1",
                    "participant-behavior-history-event-stream-v1",
                ],
                "supported_decision_surface_modes": ["policy-directed"],
                "tool_affordance_expectations": ["shell"],
                "exposure_policy_kinds": ["task-statement"],
            },
        }
    )
    selection = ParticipantImplementationSelectionModel.model_validate(
        {
            "participant_address": participant_address,
            "implementation_identity": {"name": "aptl-admit-probe", "version": "1.0.0"},
            "manifest_ref": "registry://aptl-participant-implementation-manifest",
            "manifest_digest": "sha256:" + "2" * 64,
            "selected_decision_surface_mode": "policy-directed",
            "participant_contract_versions": [
                "participant-episode-state-envelope-v1",
                "participant-behavior-history-event-stream-v1",
            ],
            "exposure_policy": {
                "policy_id": "aptl-admit-probe-policy",
                "exposure_policy_kinds": ["task-statement"],
                "disclosed_refs": ["scenario.aptl-admit-probe"],
            },
        }
    )
    return ParticipantActionAdmissionRequest(
        participant_address=participant_address,
        action_contract_address="participant.action-contract.aptl-admit-probe",
        observation_boundary_address="participant.observation-boundary.aptl-admit-probe",
        action_instance_id="aptl-admit-probe-action",
        implementation_manifest=manifest,
        implementation_selection=selection,
    )


def _aptl_runtime_and_control_plane(tmp_path):
    """Return (participant_runtime, control_plane) for an APTL runtime target."""
    from aces_runtime.control_plane import RuntimeControlPlane

    from aptl.backends.aces import create_aptl_runtime_target

    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        backend=MagicMock(),
    )
    return target.participant_runtime, RuntimeControlPlane(target)


def test_admit_action_records_binding_events_on_live_episode(tmp_path):
    """admit_action records the three binding events against a live episode."""
    runtime, control_plane = _aptl_runtime_and_control_plane(tmp_path)
    participant = "participant.behavior.aptl-admit-probe"
    control_plane.initialize_participant_episode(participant)

    result = runtime.admit_action(
        _participant_admission_request(participant), control_plane.snapshot
    )

    assert result.success is True
    events = runtime.behavior_history()[participant]
    assert [event["event_type"] for event in events] == [
        "action_attempted",
        "state_transition_recorded",
        "observation_emitted",
    ]


def test_admit_action_fails_without_live_episode(tmp_path):
    """admit_action fails closed when there is no initialized episode."""
    runtime, control_plane = _aptl_runtime_and_control_plane(tmp_path)
    participant = "participant.behavior.aptl-admit-probe"

    result = runtime.admit_action(
        _participant_admission_request(participant), control_plane.snapshot
    )

    assert result.success is False
    assert participant not in runtime.behavior_history()


def test_admit_action_fails_after_terminate(tmp_path):
    """admit_action fails closed once the participant episode is terminated."""
    from aces_contracts.participant_episode import ParticipantEpisodeTerminalReason

    runtime, control_plane = _aptl_runtime_and_control_plane(tmp_path)
    participant = "participant.behavior.aptl-admit-probe"
    control_plane.initialize_participant_episode(participant)
    control_plane.terminate_participant_episode(
        participant, terminal_reason=ParticipantEpisodeTerminalReason.COMPLETED
    )

    result = runtime.admit_action(
        _participant_admission_request(participant), control_plane.snapshot
    )

    assert result.success is False


def test_start_aces_scenario_uses_parser_runtime_manager_and_backend(
    mocker,
    tmp_path,
):
    from aptl.backends import aces

    _write_compose(
        tmp_path,
        {
            "wazuh.manager": ["wazuh"],
            "kali": ["kali"],
            "aptl-otel-collector": ["otel"],
        },
    )
    scenario = object()
    parser = mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=scenario)
    calls: dict[str, object] = {}

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            calls["planned_scenario"] = parsed_scenario
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.wazuh-manager", "techvault.kali")
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"wazuh": True, "kali": True, "victim": False},
    )

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is True
    parser.assert_called_once_with(
        tmp_path / "scenarios" / "techvault-operational.sdl.yaml"
    )
    assert calls == {"planned_scenario": scenario}
    backend.start.assert_called_once_with(["wazuh", "kali", "otel"])


def test_start_aces_scenario_uses_selected_scenario_path(mocker, tmp_path):
    from aptl.backends import aces

    _write_compose(tmp_path, {"wazuh.manager": ["wazuh"]})
    scenario = object()
    parser = mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=scenario)

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            assert parsed_scenario is scenario
            return _FakeExecutionPlan(_plan_for_nodes("techvault.wazuh-manager"))

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"wazuh": True})
    selected = tmp_path / "scenarios" / "custom.sdl.yaml"

    result = aces.start_aces_scenario(tmp_path, config, backend, scenario_path=selected)

    assert result.lab_result.success is True
    parser.assert_called_once_with(selected)


def _workflow_orchestration_plan():
    """Compile a minimal workflow scenario into its ACES orchestration plan."""
    from textwrap import dedent

    from aces_processor.compiler import compile_runtime_model
    from aces_processor.planner import plan as aces_plan
    from aces_sdl.parser import parse_sdl

    from aptl.backends.aces_manifest import create_aptl_manifest

    scenario = parse_sdl(
        dedent(
            """
            name: wf
            nodes:
              vm:
                type: vm
                os: linux
                resources: {ram: 1 gib, cpu: 1}
                conditions: {health: ops}
                roles: {ops: operator}
            conditions:
              health: {command: /bin/true, interval: 15}
            entities:
              blue: {role: blue}
            objectives:
              validate:
                entity: blue
                success: {conditions: [health]}
            workflows:
              response:
                start: run
                steps:
                  run: {type: objective, objective: validate, on-success: finish}
                  finish: {type: end}
            """
        )
    )
    return aces_plan(
        compile_runtime_model(scenario), create_aptl_manifest()
    ).orchestration


def test_start_aces_scenario_submits_orchestration_for_workflow_scenario(
    mocker, tmp_path
):
    """A scenario carrying workflows routes through the control plane's
    orchestration submission (not just provisioning), and the lab still starts."""
    from aces_contracts.runtime_state import OperationState

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())
    orchestration = _workflow_orchestration_plan()
    assert (
        orchestration.actionable_operations
    )  # guard: the plan really carries workflows

    submit_calls: list[str] = []

    class FakeControlPlane:
        def __init__(self, target, initial_snapshot=None):
            del target, initial_snapshot

        def submit_provisioning(self, plan):
            submit_calls.append("provisioning")
            receipt = MagicMock()
            receipt.operation_id = "prov"
            receipt.diagnostics = []
            return receipt

        def submit_orchestration(self, plan):
            submit_calls.append("orchestration")
            receipt = MagicMock()
            receipt.operation_id = "orch"
            receipt.diagnostics = []
            return receipt

        def get_operation(self, operation_id):
            status = MagicMock()
            status.state = OperationState.SUCCEEDED
            status.diagnostics = []
            return status

        def get_snapshot(self):
            return RuntimeSnapshot()

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"), orchestration=orchestration
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    mocker.patch("aptl.backends.aces.RuntimeControlPlane", FakeControlPlane)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is True
    # The orchestration block actually ran: without it, submit_calls would omit
    # "orchestration" even though provisioning still succeeds. (Profile selection
    # for backend.start is covered by the provisioning-focused tests above; here
    # the control plane is faked to observe submission routing.)
    assert submit_calls == ["provisioning", "orchestration"]


def test_start_aces_scenario_fails_when_provisioning_backend_fails(mocker, tmp_path):
    """A deployment-backend failure surfaces as a failed control-plane phase."""
    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(_plan_for_nodes("techvault.victim"))

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=False, error="backend boom")
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is False
    assert result.lab_result.error


def test_start_aces_scenario_fails_when_orchestration_fails(mocker, tmp_path):
    """An orchestration-phase failure (provisioning already applied) surfaces as
    a failed lab start, not a silent success."""
    from aces_contracts.planning import ChangeAction, OrchestrationOp, OrchestrationPlan

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())
    # A workflow op with no compiled result_contract makes AptlOrchestrator.start
    # fail closed, which the control plane reports as a failed operation.
    bad_orchestration = OrchestrationPlan(
        resources={},
        operations=[
            OrchestrationOp(
                action=ChangeAction.CREATE,
                address="orchestration.workflow.bad",
                resource_type="workflow",
                payload={"name": "bad"},
            )
        ],
    )

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"), orchestration=bad_orchestration
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is False
    assert result.lab_result.error


def test_start_aces_scenario_submits_evaluation_for_objective_scenario(
    mocker, tmp_path
):
    """A scenario carrying objectives routes through the control plane's
    evaluation submission after provisioning and orchestration."""
    from aces_contracts.planning import ChangeAction, EvaluationOp, EvaluationPlan
    from aces_contracts.runtime_state import OperationState

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())
    orchestration = _workflow_orchestration_plan()
    evaluation = EvaluationPlan(
        resources={},
        operations=[
            EvaluationOp(
                action=ChangeAction.CREATE,
                address="evaluation.objective.validate",
                resource_type="objective",
                payload={"name": "validate"},
            )
        ],
        startup_order=(),
    )

    submit_calls: list[str] = []

    class FakeControlPlane:
        def __init__(self, target, initial_snapshot=None):
            del target, initial_snapshot

        def submit_provisioning(self, plan):
            submit_calls.append("provisioning")
            receipt = MagicMock()
            receipt.operation_id = "prov"
            receipt.diagnostics = []
            return receipt

        def submit_orchestration(self, plan):
            submit_calls.append("orchestration")
            receipt = MagicMock()
            receipt.operation_id = "orch"
            receipt.diagnostics = []
            return receipt

        def submit_evaluation(self, plan):
            submit_calls.append("evaluation")
            receipt = MagicMock()
            receipt.operation_id = "eval"
            receipt.diagnostics = []
            return receipt

        def get_operation(self, operation_id):
            status = MagicMock()
            status.state = OperationState.SUCCEEDED
            status.diagnostics = []
            return status

        def get_snapshot(self):
            return RuntimeSnapshot()

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"),
                orchestration=orchestration,
                evaluation=evaluation,
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    mocker.patch("aptl.backends.aces.RuntimeControlPlane", FakeControlPlane)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is True
    assert submit_calls == ["provisioning", "orchestration", "evaluation"]


def test_start_aces_scenario_drives_workflows_after_registration(mocker, tmp_path):
    """After orchestration registers workflows, lab start invokes drive_workflows."""
    from aces_contracts.runtime_state import OperationState

    from aptl.backends import aces
    from aptl.backends.aces_orchestrator import AptlOrchestrator

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())
    orchestration = _workflow_orchestration_plan()
    drive_calls: list[dict[str, object]] = []

    class RecordingOrchestrator(AptlOrchestrator):
        def drive_workflows(self, **kwargs):
            drive_calls.append(kwargs)
            return super().drive_workflows(**kwargs)

    class FakeControlPlane:
        def __init__(self, target, initial_snapshot=None):
            self.target = target

        def submit_provisioning(self, plan):
            receipt = MagicMock()
            receipt.operation_id = "prov"
            receipt.diagnostics = []
            return receipt

        def submit_orchestration(self, plan):
            receipt = MagicMock()
            receipt.operation_id = "orch"
            receipt.diagnostics = []
            if self.target.orchestrator is not None:
                self.target.orchestrator.start(plan, RuntimeSnapshot())
            return receipt

        def submit_evaluation(self, plan):
            receipt = MagicMock()
            receipt.operation_id = "eval"
            receipt.diagnostics = []
            return receipt

        def get_operation(self, operation_id):
            status = MagicMock()
            status.state = OperationState.SUCCEEDED
            status.diagnostics = []
            return status

        def get_snapshot(self):
            return RuntimeSnapshot()

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"),
                orchestration=orchestration,
            )

    def fake_create_target(*, project_dir, config, backend):
        from aptl.backends.aces_participant_runtime import AptlParticipantRuntime

        target = aces.RuntimeTarget(
            name=aces.APTL_ACES_TARGET_NAME,
            manifest=aces.create_aptl_manifest(),
            provisioner=aces.AptlProvisioner(
                project_dir=project_dir,
                config=config,
                deployment_backend=backend,
            ),
            orchestrator=RecordingOrchestrator(),
            evaluator=aces.AptlEvaluator(),
            participant_runtime=AptlParticipantRuntime(deployment_backend=backend),
        )
        return target

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    mocker.patch("aptl.backends.aces.RuntimeControlPlane", FakeControlPlane)
    mocker.patch("aptl.backends.aces.create_aptl_runtime_target", fake_create_target)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is True
    assert drive_calls
    assert drive_calls[0]["evaluation_results"] == {}


def test_start_aces_scenario_fails_closed_on_evaluator_plan_error(mocker, tmp_path):
    """A planner error in the evaluation domain must fail closed."""
    from aces_contracts.diagnostics import Diagnostic, Severity

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())

    evaluator_error = Diagnostic(
        code="evaluator.unsupported-section",
        domain="evaluation",
        address="evaluation.metrics.score",
        message="Scenario requires unsupported evaluation section.",
        severity=Severity.ERROR,
    )

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"),
                is_valid=False,
                diagnostics=[evaluator_error],
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is False
    assert result.lab_result.error
    backend.start.assert_not_called()


def test_start_aces_scenario_fails_closed_on_provisioning_plan_error(mocker, tmp_path):
    """A provisioning planner error must fail closed before lab standup."""
    from aces_contracts.diagnostics import Diagnostic, Severity

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())

    provisioning_error = Diagnostic(
        code="provisioning.ordering.cycle",
        domain="provisioning",
        address="provision.node.techvault.victim",
        message="Provisioning ordering cycle detected.",
        severity=Severity.ERROR,
    )

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"),
                is_valid=False,
                diagnostics=[provisioning_error],
            )

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    backend = MagicMock()
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.lab_result.success is False
    assert result.lab_result.error
    backend.start.assert_not_called()


def test_provisioner_profiles_are_derived_from_plan_content(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "victim": ["victim"],
            "aptl-otel-collector": ["otel"],
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"kali": True, "victim": True, "wazuh": False},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    first = provisioner.apply(_plan_for_nodes("scenario-a.kali"), RuntimeSnapshot())
    second = provisioner.apply(_plan_for_nodes("scenario-b.victim"), RuntimeSnapshot())

    assert first.success is True
    assert second.success is True
    assert backend.start.call_args_list[0].args == (["kali", "otel"],)
    assert backend.start.call_args_list[1].args == (["victim", "otel"],)


def test_provisioner_closes_subset_dependency_profiles_before_start(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose_graph(
        tmp_path,
        {
            "webapp": (["enterprise"], []),
            "db": (["soc"], ["wazuh.manager"]),
            "wazuh.manager": (["wazuh"], []),
            "aptl-otel-collector": (["otel"], []),
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "soc": True, "wazuh": True},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_for_resources(_node_resource_with_dependencies("techvault.webapp", "db")),
        RuntimeSnapshot(),
    )

    assert result.success is True
    backend.start.assert_called_once_with(["wazuh", "enterprise", "soc", "otel"])
    assert result.details["realization"]["profiles"] == ["enterprise", "soc", "wazuh"]


def test_provisioner_treats_compose_network_dependency_as_network_support(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose_graph(
        tmp_path,
        {
            "webapp": (["enterprise"], []),
            "aptl-otel-collector": (["otel"], []),
        },
        networks={"webapp": ["internal-net"]},
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"enterprise": True})
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_for_resources(
            _node_resource_with_dependencies("techvault.webapp", "internal-net")
        ),
        RuntimeSnapshot(),
    )

    assert result.success is True
    assert all(
        diagnostic.code != "aptl.provisioner.dependency-unresolved"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_called_once_with(["enterprise", "otel"])


def test_provisioner_rejects_disabled_dependency_profile(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose_graph(
        tmp_path,
        {
            "webapp": (["enterprise"], ["db"]),
            "db": (["wazuh"], []),
            "aptl-otel-collector": (["otel"], []),
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "wazuh": False},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_for_resources(_node_resource_with_dependencies("techvault.webapp", "db")),
        RuntimeSnapshot(),
    )

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.dependency-profile-disabled"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_rejects_invalid_compose_project(tmp_path):
    """An activated profile service with an excluded depends_on must fail fast.

    workstation (enterprise) depends on wazuh-manager (wazuh). Selecting
    enterprise without wazuh hands `docker compose --profile` an invalid project
    even though only webapp is declared, because the profile activates every
    enterprise service. The provisioner refuses before calling backend.start,
    and node-level dependency closure (which only walks declared nodes) does not
    catch it.
    """
    from aptl.backends.aces import AptlProvisioner

    _write_compose_graph(
        tmp_path,
        {
            "webapp": (["enterprise"], []),
            "workstation": (["enterprise"], ["wazuh-manager"]),
            "wazuh-manager": (["wazuh"], []),
            "aptl-otel-collector": (["otel"], []),
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "wazuh": False},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_for_resources(_node_resource("techvault.webapp")), RuntimeSnapshot()
    )

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.compose-project-invalid"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_rejects_missing_declared_dependency(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose_graph(
        tmp_path,
        {
            "webapp": (["enterprise"], []),
            "aptl-otel-collector": (["otel"], []),
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"enterprise": True})
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_for_resources(_node_resource_with_dependencies("techvault.webapp", "db")),
        RuntimeSnapshot(),
    )

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.dependency-unresolved"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_rejects_missing_compose_dependency(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose_graph(
        tmp_path,
        {
            "webapp": (["enterprise"], ["missing-db"]),
            "aptl-otel-collector": (["otel"], []),
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"enterprise": True})
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_for_resources(_node_resource("techvault.webapp")),
        RuntimeSnapshot(),
    )

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.compose-dependency-unresolved"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_rejects_ambiguous_declared_dependency(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose_graph(
        tmp_path,
        {
            "webapp": (["enterprise"], []),
            "db": (["soc"], []),
            "aptl-db": (["wazuh"], []),
            "aptl-otel-collector": (["otel"], []),
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "soc": True, "wazuh": True},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_for_resources(_node_resource_with_dependencies("techvault.webapp", "db")),
        RuntimeSnapshot(),
    )

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.dependency-ambiguous"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_realization_details_follow_distinct_plan_content(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "victim": ["victim"],
            "aptl-otel-collector": ["otel"],
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(
        lab={"name": "test"},
        containers={"kali": True, "victim": True, "wazuh": False},
    )
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )
    attacker = _node_resource("exercise-a.kali")
    attacker.payload["spec"]["node"]["services"] = [
        {"name": "ssh-control", "port": 22, "protocol": "tcp"}
    ]
    target = _node_resource("exercise-b.victim")
    target.payload["spec"]["node"]["services"] = [
        {"name": "web-target", "port": 8080, "protocol": "tcp"}
    ]

    first = provisioner.apply(_plan_for_resources(attacker), RuntimeSnapshot())
    second = provisioner.apply(_plan_for_resources(target), RuntimeSnapshot())

    assert first.success is True
    assert second.success is True
    assert (
        first.details["realization"]["nodes"] != second.details["realization"]["nodes"]
    )
    assert first.details["realization"]["nodes"][0]["services"] == ["ssh-control"]
    assert second.details["realization"]["nodes"][0]["services"] == ["web-target"]


def test_provisioner_rejects_missing_node_realization_even_with_techvault_metadata(
    tmp_path,
):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    resource = PlannedResource(
        address="provision.node.techvault",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="node",
        payload={
            "name": "techvault",
            "metadata": {"scenario": "techvault"},
            "spec": {"node": {"description": "metadata-only node"}},
        },
    )

    result = provisioner.apply(_plan_for_resources(resource), RuntimeSnapshot())

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.node-profile-unresolved"
        and diagnostic.address == resource.address
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_rejects_supported_placement_without_declared_target(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    node = _node_resource("scenario.kali")
    placement = PlannedResource(
        address="provision.content-placement.payload",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "payload",
            "content_name": "payload.exe",
            "target_node": "missing-node",
        },
    )

    result = provisioner.apply(_plan_for_resources(node, placement), RuntimeSnapshot())

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.binding-target-unresolved"
        and diagnostic.address == placement.address
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_provisioner_records_supported_placement_realizations(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "aptl-otel-collector": ["otel"],
        },
    )
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    node = _node_resource("scenario.kali")
    feature = PlannedResource(
        address="provision.feature-binding.ssh",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="feature-binding",
        payload={
            "name": "ssh-feature",
            "feature_name": "ssh",
            "node_name": "scenario.kali",
        },
    )
    content = PlannedResource(
        address="provision.content-placement.payload",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "payload",
            "content_name": "payload.exe",
            "target_address": node.address,
        },
    )
    account = PlannedResource(
        address="provision.account-placement.operator",
        domain=RuntimeDomain.PROVISIONING,
        resource_type="account-placement",
        payload={
            "name": "operator",
            "account_name": "operator",
            "node_name": "scenario.kali",
        },
    )

    result = provisioner.apply(
        _plan_for_resources(node, feature, content, account), RuntimeSnapshot()
    )

    assert result.success is True
    placements = result.details["realization"]["placements"]
    assert {placement["resource_type"] for placement in placements} == {
        "account-placement",
        "content-placement",
        "feature-binding",
    }
    assert {placement["target_address"] for placement in placements} == {node.address}
    assert result.details["realization"]["resource_counts"] == {
        "account-placement": 1,
        "content-placement": 1,
        "feature-binding": 1,
        "node": 1,
    }


def test_provisioner_rejects_unsupported_resource_type(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )

    result = provisioner.apply(
        _plan_with_resource_type("packet-capture"), RuntimeSnapshot()
    )

    assert result.success is False
    assert any(
        diagnostic.code == "aptl.provisioner.unsupported-resource-type"
        for diagnostic in result.diagnostics
    )
    backend.start.assert_not_called()


def test_aces_backend_does_not_import_legacy_sdl_parser():
    aces_module = Path(__file__).resolve().parents[1] / "src/aptl/backends/aces.py"
    source = aces_module.read_text()

    assert "aptl.core.sdl" not in source
    assert "ScenarioDefinition" not in source


def test_start_aces_scenario_returns_aces_start_outcome(tmp_path):
    """start_aces_scenario returns AcesStartOutcome, not just LabResult."""
    from unittest.mock import patch as _patch, MagicMock as _MagicMock

    from aces_contracts.planning import (
        EvaluationPlan,
        OrchestrationPlan,
    )
    from aces_contracts.runtime_state import ApplyResult, OperationState, RuntimeSnapshot

    from aptl.backends.aces import AcesStartOutcome, start_aces_scenario
    from aptl.core.config import AptlConfig

    _write_compose(tmp_path, {"aptl-victim": ["victim"]})
    (tmp_path / "scenarios").mkdir()
    sdl_path = tmp_path / "scenarios" / "test.sdl.yaml"
    sdl_path.write_text(
        "kind: ScenarioDefinition\napiVersion: v1\nmetadata:\n  name: test\nspec:\n  nodes: []\n"
    )

    backend = _MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"})

    op_status = _MagicMock()
    op_status.state = OperationState.SUCCEEDED
    op_status.diagnostics = []

    apply_result = ApplyResult(
        success=True,
        snapshot=RuntimeSnapshot(),
        diagnostics=[],
    )

    with (
        _patch("aptl.backends.aces.parse_sdl_file") as mock_parse,
        _patch("aptl.backends.aces.RuntimeManager") as mock_manager,
        _patch("aptl.backends.aces.RuntimeControlPlane") as mock_cp,
    ):
        mock_scenario = _MagicMock()
        mock_parse.return_value = mock_scenario

        mock_plan = _MagicMock()
        mock_plan.diagnostics = []
        mock_plan.base_snapshot = RuntimeSnapshot()
        mock_plan.orchestration.actionable_operations = []
        mock_plan.evaluation.actionable_operations = []
        mock_plan.provisioning = _MagicMock()
        mock_manager.return_value.plan.return_value = mock_plan

        mock_control = _MagicMock()
        mock_cp.return_value = mock_control
        receipt = _MagicMock()
        receipt.operation_id = "op-1"
        mock_control.submit_provisioning.return_value = receipt
        mock_control.get_operation.return_value = op_status
        mock_control.get_snapshot.return_value = RuntimeSnapshot()

        result = start_aces_scenario(tmp_path, config, backend, scenario_path=sdl_path)

    assert isinstance(result, AcesStartOutcome)
    assert result.lab_result.success is True
    assert isinstance(result.final_snapshot, RuntimeSnapshot)
    assert isinstance(result.realization_details, dict)
    assert isinstance(result.selected_profiles, list)


def test_drive_workflows_receives_threaded_run_store_and_run_id(tmp_path):
    """_apply_provisioning_and_orchestration threads its run_store/run_id args
    into drive_workflows (GAP 2/4): a real run store + run_id, not None."""
    from unittest.mock import MagicMock as _MagicMock

    from aces_contracts.runtime_state import OperationState

    from aptl.backends.aces import (
        AptlOrchestrator,
        _apply_provisioning_and_orchestration,
    )
    from aptl.core.runstore import LocalRunStore

    store = LocalRunStore(tmp_path / "runs")
    run_id = "run_20260101T000000Z"

    mock_orchestrator = _MagicMock(spec=AptlOrchestrator)
    mock_orchestrator.results.return_value = {"wf1": {"status": "PENDING"}}
    mock_orchestrator.drive_workflows.return_value = []

    mock_plan = _MagicMock()
    mock_plan.orchestration.actionable_operations = []
    mock_plan.evaluation.actionable_operations = []
    mock_plan.provisioning = _MagicMock()

    mock_target = _MagicMock()
    mock_target.orchestrator = mock_orchestrator
    mock_target.evaluator = None
    mock_target.provisioner = None

    receipt = _MagicMock()
    receipt.operation_id = "op-prov"
    op_status = _MagicMock()
    op_status.state = OperationState.SUCCEEDED
    op_status.diagnostics = []

    mock_cp = _MagicMock()
    mock_cp.submit_provisioning.return_value = receipt
    mock_cp.get_operation.return_value = op_status

    failure, _, _ = _apply_provisioning_and_orchestration(
        mock_cp, mock_plan, mock_target, run_store=store, run_id=run_id
    )

    mock_orchestrator.drive_workflows.assert_called_once_with(
        evaluation_results={},
        run_store=store,
        run_id=run_id,
    )
    assert failure is None


def test_drive_workflows_persists_workflow_result_under_run_dir(tmp_path):
    """A real AptlOrchestrator with a registered workflow persists its result
    and history under the run dir when run_store + run_id are threaded."""
    from aces_contracts.workflow import WorkflowExecutionState, WorkflowStatus

    from aptl.backends.aces_orchestrator import AptlOrchestrator
    from aptl.core.runstore import LocalRunStore
    from aptl.core.runtime.workflow_engine import WorkflowRunRecord

    store = LocalRunStore(tmp_path / "runs")
    run_id = "run_20260101T000000Z"
    store.create_run(run_id)

    orchestrator = AptlOrchestrator()
    address = "exercise.workflow.demo"
    safe_address = address.replace("/", "_")

    # Register a workflow payload and a PENDING engine record, then drive.
    orchestrator._workflow_payloads = {address: {"steps": []}}

    pending_payload = WorkflowExecutionState(
        workflow_status=WorkflowStatus.PENDING,
        run_id="wf-run-1",
        started_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    ).to_payload()
    done_payload = WorkflowExecutionState(
        workflow_status=WorkflowStatus.SUCCEEDED,
        run_id="wf-run-1",
        started_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:01Z",
        terminal_reason="completed",
    ).to_payload()

    record_pending = WorkflowRunRecord(
        result=pending_payload,
        history=[{"event": "registered"}],
    )
    record_done = WorkflowRunRecord(
        result=done_payload,
        history=[{"event": "registered"}, {"event": "completed"}],
    )

    class _FakeEngine:
        def __init__(self):
            self._calls = 0

        def get(self, addr):
            del addr
            # First read returns PENDING (drive precondition); reads after
            # drive() return the completed record persisted to the run store.
            self._calls += 1
            return record_pending if self._calls == 1 else record_done

        def drive(self, addr, payload, *, objective_outcomes):
            del addr, payload, objective_outcomes

    orchestrator._engine = _FakeEngine()
    orchestrator._sync_from_engine = lambda: None

    diagnostics = orchestrator.drive_workflows(run_store=store, run_id=run_id)

    assert diagnostics == []
    run_dir = store.get_run_path(run_id)
    result_path = run_dir / "orchestration" / safe_address / "result.json"
    history_path = run_dir / "orchestration" / safe_address / "history.jsonl"
    assert result_path.exists()
    assert history_path.exists()


def test_apply_provisioning_populates_realization_and_profiles(tmp_path):
    """GAP 1: _apply_provisioning_and_orchestration returns NON-EMPTY
    realization_details (with a 'nodes' key) and selected_profiles for a
    scenario that realizes nodes, by interpreting the provisioning plan."""
    from unittest.mock import MagicMock as _MagicMock

    from aces_contracts.runtime_state import OperationState

    from aptl.backends.aces import AptlProvisioner, _apply_provisioning_and_orchestration
    from aptl.core.config import AptlConfig

    _write_compose(tmp_path, {"victim": ["victim"]})
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=_MagicMock(),
    )

    plan = _plan_for_resources(_node_resource("techvault.victim"))

    mock_plan = _MagicMock()
    mock_plan.orchestration.actionable_operations = []
    mock_plan.evaluation.actionable_operations = []
    mock_plan.provisioning = plan

    mock_target = _MagicMock()
    mock_target.orchestrator = None
    mock_target.evaluator = None
    mock_target.provisioner = provisioner

    receipt = _MagicMock()
    receipt.operation_id = "op-prov"
    op_status = _MagicMock()
    op_status.state = OperationState.SUCCEEDED
    op_status.diagnostics = []

    mock_cp = _MagicMock()
    mock_cp.submit_provisioning.return_value = receipt
    mock_cp.get_operation.return_value = op_status

    failure, realization_details, selected_profiles = (
        _apply_provisioning_and_orchestration(mock_cp, mock_plan, mock_target)
    )

    assert failure is None
    assert isinstance(realization_details, dict)
    assert "nodes" in realization_details
    assert len(realization_details["nodes"]) >= 1
    assert "victim" in selected_profiles
