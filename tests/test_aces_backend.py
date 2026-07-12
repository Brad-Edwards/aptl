"""Tests for the APTL ACES runtime handoff."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFORMANCE_SCENARIO = PROJECT_ROOT / "scenarios" / "techvault-defensive-min.sdl.yaml"


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


def _network_resource(
    network_name: str,
    *,
    cidr: str | None = None,
    gateway: str | None = None,
    internal: bool | None = None,
) -> PlannedResource:
    address = f"provision.network.{network_name}"
    properties = {
        key: value
        for key, value in {
            "cidr": cidr,
            "gateway": gateway,
            "internal": internal,
        }.items()
        if value is not None
    }
    return PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="network",
        payload={
            "name": network_name,
            "spec": {"infrastructure": {"properties": properties}},
        },
    )


def _node_with_static_address(
    node_name: str,
    *,
    links: tuple[str, ...],
    network: str,
    address: str,
) -> PlannedResource:
    node = _node_resource(node_name)
    node.payload["spec"]["infrastructure"]["links"] = list(links)
    node.payload["spec"]["infrastructure"]["properties"] = [{network: address}]
    return node


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


def _execution_plan_with_realization_requirements():
    from textwrap import dedent

    from aces_processor.compiler import compile_runtime_model
    from aces_processor.planner import plan
    from aces_sdl.parser import parse_sdl

    from aptl.backends.aces_manifest import create_aptl_manifest

    scenario = parse_sdl(
        dedent(
            """
            name: disclosure-test
            nodes:
              vm:
                type: vm
                os: linux
                resources: {ram: 1 gib, cpu: 1}
            """
        )
    )
    return plan(compile_runtime_model(scenario), create_aptl_manifest())


def _realize_profiles(call) -> list[str]:
    """Return profile names from a DeploymentRealizationSpec mock call."""

    return list(call.args[0].profiles)


def _diagnostic_codes_for_resources(
    tmp_path: Path,
    *resources: PlannedResource,
) -> set[str]:
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"kali": ["kali"], "victim": ["victim"]})
    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(*resources),
        project_dir=tmp_path,
        config=AptlConfig(
            lab={"name": "test"},
            containers={"kali": True, "victim": True},
        ),
    )
    return {diagnostic.code for diagnostic in realization.diagnostics}


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


def test_aptl_target_passes_provisioning_only_conformance():
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT,
        config=config,
        backend=backend,
    )

    report = run_target_conformance(
        target,
        profile="provisioning-only",
        reference_scenario=CONFORMANCE_SCENARIO,
    )

    assert report.passed is True, [d.code for d in report.diagnostics]
    assert report.unsupported_contract_gaps == ()
    assert report.unsupported_capability_gaps == ()


def test_aptl_target_passes_orchestration_evaluation_conformance():
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT,
        config=config,
        backend=backend,
    )

    report = run_target_conformance(
        target,
        profile="orchestration-evaluation",
        reference_scenario=CONFORMANCE_SCENARIO,
    )

    assert report.passed is True, [d.code for d in report.diagnostics]
    assert report.unsupported_contract_gaps == ()
    assert report.unsupported_capability_gaps == ()
    assert all(case.passed for case in report.cases), [
        (case.name, [d.message for d in case.diagnostics])
        for case in report.cases
        if not case.passed
    ]


def test_aptl_target_passes_full_remote_control_plane_conformance():
    from aces_conformance.conformance import run_target_conformance

    from aptl.backends.aces import create_aptl_runtime_target

    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"})
    target = create_aptl_runtime_target(
        project_dir=PROJECT_ROOT,
        config=config,
        backend=backend,
    )

    report = run_target_conformance(
        target,
        profile="full-remote-control-plane",
        reference_scenario=CONFORMANCE_SCENARIO,
    )

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


def test_paper_participant_action_uses_compiled_addresses_and_boundary_markers(
    tmp_path,
):
    import subprocess

    from aces_processor.compiler import compile_runtime_model
    from aces_contracts.runtime_state import OperationState
    from aces_runtime.control_plane import RuntimeControlPlane
    from aces_runtime.manager import RuntimeManager
    from aces_sdl import parse_sdl_file

    from aptl.backends.aces import create_aptl_runtime_target
    from aptl.backends.aces_participant_actions import (
        DEFAULT_PARTICIPANT_ACTIONS,
        participant_action_specs_from_runtime_model,
    )

    participant_address = "participant.behavior.paper-agent"
    action_contract_address = "participant.action-contract.probe-customer-portal-login"
    observation_boundary_address = "participant.observation-boundary.paper-agent-view"

    assert participant_address not in DEFAULT_PARTICIPANT_ACTIONS
    assert not (
        Path(__file__).resolve().parents[1]
        / "src/aptl/backends/aces_paper_participant_actions.py"
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
    project_root = Path(__file__).resolve().parents[1]
    scenario = parse_sdl_file(project_root / "scenarios" / "paper-agent-loop.sdl.yaml")
    model = compile_runtime_model(scenario)
    config = AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "kali": True, "wazuh": True},
    )
    plan_target = create_aptl_runtime_target(
        project_dir=project_root,
        config=config,
        backend=MagicMock(),
    )
    plan = RuntimeManager(plan_target).plan(scenario)
    participant_action_specs = participant_action_specs_from_runtime_model(
        model,
        provisioning_plan=plan.provisioning,
        project_dir=project_root,
        config=config,
    )
    target = create_aptl_runtime_target(
        project_dir=tmp_path,
        config=config,
        backend=backend,
        participant_action_specs=participant_action_specs,
    )
    control_plane = RuntimeControlPlane(target)

    receipt = control_plane.initialize_participant_episode(participant_address)
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
    behavior = control_plane.snapshot.participant_behavior_history[participant_address]
    assert behavior[0]["action_contract_address"] == action_contract_address
    assert behavior[-1]["observation_boundary_address"] == observation_boundary_address
    assert "boundary_db=blocked" in behavior[-1]["details"]["stdout_excerpt"]
    entries = control_plane.snapshot.entries
    assert (
        entries[participant_address].payload["participant_address"]
        == participant_address
    )
    assert entries[action_contract_address].payload["action_name"] == (
        "probe-customer-portal-login"
    )
    assert entries[observation_boundary_address].payload["boundary_name"] == (
        "paper-agent-view"
    )
    assert "Kali victim SSH" not in str(entries[action_contract_address].payload)
    assert "kali-victim-ssh" not in str(entries[observation_boundary_address].payload)
    shared_state_records = getattr(
        control_plane.snapshot, "shared_state_records", {}
    )
    assert {
        record["state_scope"] for record in shared_state_records.values()
    } == {participant_address}
    assert participant_action_specs[participant_address].target_refs == (
        "container:aptl-kali",
        "container:aptl-webapp",
        "http://172.20.1.20:8080/login",
        "boundary-negative:tcp:172.20.2.11:5432",
        "boundary-negative:tcp:172.20.2.30:55000",
    )


def test_runtime_model_without_paper_artifacts_registers_no_paper_action():
    from aces_runtime.manager import RuntimeManager
    from aces_sdl import parse_sdl_file

    from aptl.backends.aces import create_aptl_runtime_target
    from aptl.backends.aces_participant_actions import (
        participant_action_specs_from_runtime_model,
    )

    class EmptyModel:
        participant_behaviors = {}
        action_contracts = {}
        observation_boundaries = {}
        content_placements = {}

    project_root = Path(__file__).resolve().parents[1]
    config = AptlConfig(
        lab={"name": "test"},
        containers={"enterprise": True, "kali": True, "wazuh": True},
    )
    scenario = parse_sdl_file(project_root / "scenarios" / "paper-agent-loop.sdl.yaml")
    target = create_aptl_runtime_target(
        project_dir=project_root,
        config=config,
        backend=MagicMock(),
    )
    plan = RuntimeManager(target).plan(scenario)

    assert (
        participant_action_specs_from_runtime_model(
            EmptyModel(),
            provisioning_plan=plan.provisioning,
            project_dir=project_root,
            config=config,
        )
        == {}
    )


def test_runtime_bindings_skips_non_yaml_content_text():
    """Free-form content text must be skipped, not crash ``_runtime_bindings``.

    Regression (issue #689 live-boot crash): a content-placement with inline
    prose (a planted file's text) reaches ``_runtime_bindings``, which
    ``yaml.safe_load()``s every content ``text`` to detect participant-binding
    specs. Multi-line prose is not a single YAML document, so ``safe_load``
    raised ``ParserError`` and crashed ``aptl lab start`` — the static gates
    never exercised the runtime boot path. Unparseable text is simply not a
    binding spec and must be skipped.
    """
    from types import SimpleNamespace

    from aptl.backends.aces_participant_bindings import _runtime_bindings

    # Faithful to the shipped fileshare-public-notice text: the space before
    # "#689" makes YAML read "#689) ..." as a comment, terminating the scalar,
    # so the following line parses as an unexpected second document (ParserError).
    prose = (
        "Welcome to TechVault Solutions file server.\n"
        "This notice is planted by the operational ACES scenario's\n"
        "content-placement realization (issue #689) — dynamically realized\n"
        "from inline text authored in techvault-operational.sdl.yaml, not\n"
        "hand-copied onto the image.\n"
    )
    model = SimpleNamespace(
        content_placements={
            "content.fileshare-public-notice": SimpleNamespace(
                spec={"text": prose}
            ),
        }
    )

    assert _runtime_bindings(model) == []


def test_start_helper_returns_specs_from_compiled_scenario(mocker):
    from aptl.backends.aces_participant_actions import (
        participant_action_specs_for_scenario,
    )

    expected = {"participant.behavior.paper-agent": MagicMock()}
    model = object()
    scenario = object()
    provisioning_plan = object()
    project_dir = Path(__file__).resolve().parents[1]
    config = AptlConfig(lab={"name": "test"})
    compile_mock = mocker.patch(
        "aptl.backends.aces_participant_actions.compile_runtime_model",
        return_value=model,
    )
    spec_mock = mocker.patch(
        "aptl.backends.aces_participant_actions."
        "participant_action_specs_from_runtime_model",
        return_value=expected,
    )

    assert (
        participant_action_specs_for_scenario(
            scenario,
            provisioning_plan=provisioning_plan,
            project_dir=project_dir,
            config=config,
        )
        == expected
    )
    compile_mock.assert_called_once_with(scenario)
    spec_mock.assert_called_once_with(
        model,
        provisioning_plan=provisioning_plan,
        project_dir=project_dir,
        config=config,
    )


def test_compose_alias_helpers_cover_string_builds_and_alpine_images():
    from aptl.backends.aces_profiles import _build_aliases, _image_aliases

    assert _image_aliases({"image": "docker.io/library/redis-alpine:7"}) == {
        "redis",
        "redis-alpine",
    }
    assert _build_aliases({"build": "containers/customer-portal"}) == {
        "customer-portal"
    }


def test_container_name_and_single_value_helpers_handle_ambiguous_inputs():
    from aptl.backends.aces_profiles import ComposeProfileIndex
    from aptl.backends.aces_realization import _container_name
    from aptl.backends.aces_realization_model import _single_or_none

    assert _single_or_none(("webapp", "db")) is None
    index = ComposeProfileIndex(
        alias_to_profiles={},
        alias_to_services={},
        services={},
    )
    assert _container_name(index, frozenset({"missing"})) is None


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    assert _realize_profiles(backend.realize.call_args) == ["wazuh", "kali", "otel"]


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.return_value = LabResult(success=False, error="backend boom")
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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.return_value = LabResult(success=True, message="ok")
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

    def fake_create_target(
        *, project_dir, config, backend, participant_action_specs=None
    ):
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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


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
    backend.realize.assert_not_called()


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    assert _realize_profiles(backend.realize.call_args_list[0]) == ["kali", "otel"]
    assert _realize_profiles(backend.realize.call_args_list[1]) == ["victim", "otel"]


def test_provisioner_passes_typed_realization_spec_to_backend(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "aptl-otel-collector": ["otel"],
        },
    )
    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"kali": True})
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=config,
        deployment_backend=backend,
    )
    node = _node_resource("red-workbench")
    node.payload["spec"]["infrastructure"]["links"] = ["redteam-net", "dmz-net"]

    result = provisioner.apply(_plan_for_resources(node), RuntimeSnapshot())

    assert result.success is True
    spec = backend.realize.call_args.args[0]
    assert list(spec.profiles) == ["kali", "otel"]
    assert len(spec.nodes) == 1
    assert spec.nodes[0].name == "red-workbench"
    assert spec.nodes[0].service_name == "kali"
    assert spec.nodes[0].container_name == "kali"
    assert spec.nodes[0].networks == ("dmz-net", "redteam-net")


def test_realization_preserves_network_static_address_assignments(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"kali": ["kali"]})
    node = _node_resource("red-workbench")
    node.payload["spec"]["infrastructure"]["links"] = ["redteam-net", "dmz-net"]
    node.payload["spec"]["infrastructure"]["properties"] = [
        {"redteam-net": "172.20.4.30"},
        {"dmz-net": "172.20.1.30"},
    ]
    dmz = _network_resource(
        "dmz-net",
        cidr="172.20.1.0/24",
        gateway="172.20.1.1",
        internal=True,
    )
    redteam = _network_resource(
        "redteam-net",
        cidr="172.20.4.0/24",
        gateway="172.20.4.1",
        internal=True,
    )

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node, dmz, redteam),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"kali": True}),
    )

    assert [diagnostic.code for diagnostic in realization.diagnostics] == []
    spec = realization.deployment_spec(["kali", "otel"])
    assert [
        (network.name, network.cidr, network.gateway, network.internal)
        for network in spec.networks
    ] == [
        ("dmz-net", "172.20.1.0/24", "172.20.1.1", True),
        ("redteam-net", "172.20.4.0/24", "172.20.4.1", True),
    ]
    assert [
        (attachment.network, attachment.ipv4_address)
        for attachment in spec.nodes[0].network_attachments
    ] == [
        ("dmz-net", "172.20.1.30"),
        ("redteam-net", "172.20.4.30"),
    ]
    node_details = realization.details()["nodes"][0]
    assert node_details["static_addresses"] == ["172.20.1.30", "172.20.4.30"]
    assert node_details["static_address_assignments"] == [
        {"network": "dmz-net", "ipv4_address": "172.20.1.30"},
        {"network": "redteam-net", "ipv4_address": "172.20.4.30"},
    ]


@pytest.mark.parametrize(
    ("resources_factory", "diagnostic_code"),
    [
        pytest.param(
            lambda: (_network_resource("dmz-net", cidr="not-a-cidr"),),
            "aptl.provisioner.network-cidr-invalid",
            id="cidr-invalid",
        ),
        pytest.param(
            lambda: (
                _network_resource(
                    "dmz-net",
                    cidr="172.20.1.0/24",
                    gateway="not-an-ip",
                ),
            ),
            "aptl.provisioner.network-gateway-invalid",
            id="gateway-invalid",
        ),
        pytest.param(
            lambda: (
                _network_resource(
                    "dmz-net",
                    cidr="172.20.1.0/24",
                    gateway="172.20.99.1",
                ),
            ),
            "aptl.provisioner.network-gateway-out-of-range",
            id="gateway-out-of-range",
        ),
        pytest.param(
            lambda: (
                _node_with_static_address(
                    "red-workbench",
                    links=("dmz-net",),
                    network="dmz-net",
                    address="not-an-ip",
                ),
                _network_resource("dmz-net", cidr="172.20.1.0/24"),
            ),
            "aptl.provisioner.network-static-address-invalid",
            id="static-address-invalid",
        ),
        pytest.param(
            lambda: (
                _node_with_static_address(
                    "red-workbench",
                    links=("dmz-net",),
                    network="dmz-net",
                    address="172.20.99.30",
                ),
                _network_resource("dmz-net", cidr="172.20.1.0/24"),
            ),
            "aptl.provisioner.network-static-address-out-of-range",
            id="static-address-out-of-range",
        ),
        pytest.param(
            lambda: (
                _node_with_static_address(
                    "red-workbench",
                    links=("dmz-net",),
                    network="dmz-net",
                    address="172.20.1.30",
                ),
                _node_with_static_address(
                    "victim",
                    links=("dmz-net",),
                    network="dmz-net",
                    address="172.20.1.30",
                ),
                _network_resource("dmz-net", cidr="172.20.1.0/24"),
            ),
            "aptl.provisioner.network-static-address-duplicate",
            id="static-address-duplicate",
        ),
        pytest.param(
            lambda: (
                _node_with_static_address(
                    "red-workbench",
                    links=("redteam-net",),
                    network="dmz-net",
                    address="172.20.1.30",
                ),
                _network_resource("dmz-net", cidr="172.20.1.0/24"),
                _network_resource("redteam-net", cidr="172.20.4.0/24"),
            ),
            "aptl.provisioner.network-static-address-unlinked",
            id="static-address-unlinked",
        ),
        pytest.param(
            lambda: (
                _network_resource("dmz-net", cidr="172.20.1.0/24"),
                _network_resource("aptl-dmz", cidr="172.20.2.0/24"),
            ),
            "aptl.provisioner.network-name-ambiguous",
            id="network-name-ambiguous",
        ),
    ],
)
def test_realization_reports_network_topology_diagnostics(
    tmp_path,
    resources_factory,
    diagnostic_code,
):
    assert diagnostic_code in _diagnostic_codes_for_resources(
        tmp_path,
        *resources_factory(),
    )


def test_realization_rejects_static_address_outside_declared_network(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"kali": ["kali"]})
    node = _node_resource("red-workbench")
    node.payload["spec"]["infrastructure"]["links"] = ["dmz-net"]
    node.payload["spec"]["infrastructure"]["properties"] = [
        {"dmz-net": "172.20.99.30"}
    ]
    dmz = _network_resource(
        "dmz-net",
        cidr="172.20.1.0/24",
        gateway="172.20.1.1",
        internal=True,
    )

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node, dmz),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"kali": True}),
    )

    assert any(
        diagnostic.code == "aptl.provisioner.network-static-address-out-of-range"
        for diagnostic in realization.diagnostics
    )


def test_realization_resolves_digest_pinned_source_image(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    digest = "sha256:" + "a" * 64
    _write_compose(tmp_path, {"db": ["enterprise"]})
    node = _node_resource("db")
    node.payload["spec"]["node"]["source"] = {
        "name": "postgres",
        "version": f"postgres@{digest}",
        "build": None,
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"enterprise": True}),
    )

    assert [diagnostic.code for diagnostic in realization.diagnostics] == []
    spec = realization.deployment_spec(["enterprise", "otel"])
    assert len(spec.images) == 1
    image = spec.images[0]
    assert image.mode == "pull"
    assert image.service_name == "db"
    assert image.image_ref == f"postgres@{digest}"
    assert image.source_name == "postgres"
    assert image.source_version == f"postgres@{digest}"


def test_realization_uses_allowed_source_when_upstream_build_path_is_note(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"wazuh-manager": ["wazuh"]})
    node = _node_resource("wazuh-manager")
    node.payload["spec"]["node"]["source"] = {
        "name": "wazuh-manager",
        "version": "4.x",
        "build": {
            "dockerfile_path": (
                "upstream Wazuh manager Dockerfile not present in APTL checkout"
            ),
            "instructions": [{"instruction": "from", "arguments": ["amazonlinux"]}],
        },
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"wazuh": True}),
    )

    assert [diagnostic.code for diagnostic in realization.diagnostics] == []
    spec = realization.deployment_spec(["wazuh", "otel"])
    assert len(spec.images) == 1
    image = spec.images[0]
    assert image.mode == "pull"
    assert image.policy_rule == "allowed-source"
    assert image.image_ref == "wazuh/wazuh-manager:4.12.0"


def test_realization_resolves_project_build_provenance(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    dockerfile = tmp_path / "containers" / "custom" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n")
    _write_compose(tmp_path, {"custom": ["enterprise"]})
    node = _node_resource("custom")
    node.payload["spec"]["node"]["source"] = {
        "name": "aptl-custom",
        "version": "aptl-custom@sha256:" + "b" * 64,
        "build": {
            "dockerfile_path": "containers/custom/Dockerfile",
            "instructions": [{"instruction": "from", "arguments": ["scratch"]}],
            "layers": [{"digest": "sha256:" + "c" * 64}],
            "source_inputs": [
                {
                    "source_path": "containers/custom/Dockerfile",
                    "checksum": "d" * 64,
                }
            ],
        },
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"enterprise": True}),
    )

    assert [diagnostic.code for diagnostic in realization.diagnostics] == []
    spec = realization.deployment_spec(["enterprise", "otel"])
    assert len(spec.images) == 1
    image = spec.images[0]
    assert image.mode == "build"
    assert image.service_name == "custom"
    assert image.image_ref == "aptl-custom:local"
    assert image.dockerfile_path == "containers/custom/Dockerfile"
    assert image.context_path == "."
    assert image.provenance == {
        "instructions": 1,
        "layers": 1,
        "source_inputs": 1,
    }
    assert realization.details()["nodes"][0]["image"]["mode"] == "build"


def test_realization_rejects_untrusted_source_without_value_leakage(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"bad": ["enterprise"]})
    node = _node_resource("bad")
    node.payload["spec"]["node"]["source"] = {
        "name": "evil.example/secret-app",
        "version": "latest",
        "build": None,
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"enterprise": True}),
    )

    diagnostics = list(realization.diagnostics)
    assert any(
        diagnostic.code == "aptl.provisioner.image-policy-rejected"
        for diagnostic in diagnostics
    )
    rendered = " ".join(diagnostic.message for diagnostic in diagnostics)
    assert "evil" not in rendered
    assert "secret-app" not in rendered
    assert "latest" not in rendered


def test_realization_rejects_digest_ref_outside_allowed_source_policy(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    digest = "sha256:" + "e" * 64
    _write_compose(tmp_path, {"db": ["enterprise"]})
    node = _node_resource("db")
    node.payload["spec"]["node"]["source"] = {
        "name": "postgres",
        "version": f"evil.example/secret-db@{digest}",
        "build": None,
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"enterprise": True}),
    )

    diagnostics = list(realization.diagnostics)
    assert any(
        diagnostic.code == "aptl.provisioner.image-policy-rejected"
        for diagnostic in diagnostics
    )
    assert realization.deployment_spec(["enterprise", "otel"]).images == ()
    rendered = " ".join(diagnostic.message for diagnostic in diagnostics)
    assert "evil" not in rendered
    assert "secret-db" not in rendered
    assert digest not in rendered


def test_realization_rejects_unresolved_source_without_default_fallback(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"custom": ["enterprise"]})
    node = _node_resource("custom")
    node.payload["spec"]["node"]["source"] = {
        "name": "unapproved-custom",
        "version": "1.0",
        "build": None,
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"enterprise": True}),
    )

    assert any(
        diagnostic.code == "aptl.provisioner.image-policy-rejected"
        for diagnostic in realization.diagnostics
    )
    assert realization.deployment_spec(["enterprise", "otel"]).images == ()


def test_realization_accepts_compose_owned_reference_source_without_override(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"customer-portal": ["enterprise"]})
    node = _node_resource("customer-portal")
    node.payload["spec"]["node"]["source"] = {
        "name": "customer-portal-app",
        "version": "reference",
        "build": None,
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"enterprise": True}),
    )

    assert [diagnostic.code for diagnostic in realization.diagnostics] == []
    assert realization.deployment_spec(["enterprise", "otel"]).images == ()


def test_realization_prefers_unique_node_alias_over_shared_source_alias(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    (tmp_path / "docker-compose.yml").write_text(
        "\n".join(
            [
                "services:",
                "  wazuh-sidecar-db:",
                "    profiles: [\"wazuh\"]",
                "    image: aptl-wazuh-sidecar:local",
                "    container_name: aptl-wazuh-sidecar-db",
                "  wazuh-sidecar-suricata:",
                "    profiles: [\"wazuh\"]",
                "    image: aptl-wazuh-sidecar:local",
                "    container_name: aptl-wazuh-sidecar-suricata",
            ]
        )
    )
    node = _node_resource("wazuh-sidecar-db")
    node.payload["spec"]["node"]["source"] = {
        "name": "aptl-wazuh-sidecar",
        "version": "local",
    }

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(node),
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}, containers={"wazuh": True}),
    )

    assert [diagnostic.code for diagnostic in realization.diagnostics] == []
    assert realization.nodes[0].backend_services == ("wazuh-sidecar-db",)
    assert realization.nodes[0].container_name == "aptl-wazuh-sidecar-db"


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    assert _realize_profiles(backend.realize.call_args) == [
        "wazuh",
        "enterprise",
        "soc",
        "otel",
    ]
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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    assert _realize_profiles(backend.realize.call_args) == ["enterprise", "otel"]


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


def test_provisioner_rejects_invalid_compose_project(tmp_path):
    """An activated profile service with an excluded depends_on must fail fast.

    workstation (enterprise) depends on wazuh-manager (wazuh). Selecting
    enterprise without wazuh hands `docker compose --profile` an invalid project
    even though only webapp is declared, because the profile activates every
    enterprise service. The provisioner refuses before calling backend.realize,
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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


def test_provisioner_rejects_supported_placement_without_declared_target(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


def _fileshare_and_ad_compose(tmp_path: Path) -> None:
    _write_compose(
        tmp_path,
        {
            "kali": ["kali"],
            "aptl-otel-collector": ["otel"],
            "fileshare": ["fileshare"],
            "ad": ["enterprise"],
        },
    )


def _content_resource(
    *,
    address: str = "provision.content-placement.notice",
    target_node: str = "scenario.fileshare",
    target_address: str,
    spec_overrides: dict | None = None,
) -> PlannedResource:
    spec = {
        "type": "file",
        "description": "",
        "target": target_node,
        "path": "public/notice.txt",
        "destination": "",
        "text": "Welcome to TechVault.",
        "source": None,
        "format": "",
        "items": [],
        "sensitive": False,
        "tags": [],
    }
    spec.update(spec_overrides or {})
    return PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="content-placement",
        payload={
            "name": "notice",
            "content_name": "notice",
            "target_node": target_node,
            "target_address": target_address,
            "spec": spec,
        },
    )


def _account_resource(
    *,
    address: str = "provision.account-placement.operator",
    node_name: str = "scenario.ad",
    target_address: str,
    spec_overrides: dict | None = None,
) -> PlannedResource:
    spec = {
        "username": "operator",
        "node": node_name,
        "groups": ["IT-Admins"],
        "password_strength": "weak",
        "auth_method": "password",
        "description": "",
        "mail": "operator@techvault.local",
        "spn": "",
        "shell": "",
        "home": "",
        "disabled": False,
    }
    spec.update(spec_overrides or {})
    return PlannedResource(
        address=address,
        domain=RuntimeDomain.PROVISIONING,
        resource_type="account-placement",
        payload={
            "name": "operator",
            "account_name": "operator",
            "node_name": node_name,
            "target_address": target_address,
            "spec": spec,
        },
    )


def test_provisioner_records_supported_placement_realizations(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _fileshare_and_ad_compose(tmp_path)
    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    node = _node_resource("scenario.kali")
    fileshare_node = _node_resource("scenario.fileshare")
    ad_node = _node_resource("scenario.ad")
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
    content = _content_resource(target_address=fileshare_node.address)
    account = _account_resource(target_address=ad_node.address)

    result = provisioner.apply(
        _plan_for_resources(node, fileshare_node, ad_node, feature, content, account),
        RuntimeSnapshot(),
    )

    assert result.success is True
    placements = result.details["realization"]["placements"]
    assert {placement["resource_type"] for placement in placements} == {
        "account-placement",
        "content-placement",
        "feature-binding",
    }
    assert result.details["realization"]["resource_counts"] == {
        "account-placement": 1,
        "content-placement": 1,
        "feature-binding": 1,
        "node": 3,
    }

    content_placement = next(
        p for p in placements if p["resource_type"] == "content-placement"
    )
    assert content_placement["content"] == {
        "address": "provision.content-placement.notice",
        "target_address": fileshare_node.address,
        "content_name": "notice",
        "volume_suffix": "fileshare_data",
        "dest_relpath": "public/notice.txt",
        "source_kind": "inline-text",
        "source_relpath": None,
        "sensitive": False,
    }

    account_placement = next(
        p for p in placements if p["resource_type"] == "account-placement"
    )
    assert account_placement["account"] == {
        "address": "provision.account-placement.operator",
        "target_address": ad_node.address,
        "username": "operator",
        "groups": ["IT-Admins"],
        "spn": "",
        "mail": "operator@techvault.local",
        "disabled": False,
    }

    # Real lowering, not counting: the typed backend spec actually passed
    # to the deployment backend carries the content/account records.
    deployment_spec = backend.realize.call_args[0][0]
    assert len(deployment_spec.content) == 1
    assert deployment_spec.content[0].dest_relpath == "public/notice.txt"
    assert deployment_spec.content[0].inline_text == "Welcome to TechVault."
    assert len(deployment_spec.accounts) == 1
    assert deployment_spec.accounts[0].username == "operator"


def _apply_single_content_placement(tmp_path, *, spec_overrides: dict) -> tuple:
    """Apply a plan with one fileshare-targeted content placement; return (result, code)."""
    from aptl.backends.aces import AptlProvisioner

    _fileshare_and_ad_compose(tmp_path)
    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    fileshare_node = _node_resource("scenario.fileshare")
    content = _content_resource(
        target_address=fileshare_node.address, spec_overrides=spec_overrides
    )
    result = provisioner.apply(
        _plan_for_resources(fileshare_node, content), RuntimeSnapshot()
    )
    codes = {d.code for d in result.diagnostics}
    return result, codes


def test_content_placement_dataset_type_fails_closed(tmp_path):
    result, codes = _apply_single_content_placement(
        tmp_path,
        spec_overrides={
            "type": "dataset",
            "text": None,
            "source": {"name": "some-package", "version": "*", "build": None},
            "items": [{"name": "item-1", "tags": [], "description": ""}],
        },
    )
    assert result.success is False
    assert "aptl.provisioner.content-placement-rejected" in codes
    assert any(
        "dataset-not-realizable" in d.message
        for d in result.diagnostics
        if d.code == "aptl.provisioner.content-placement-rejected"
    )


def test_content_placement_runtime_observed_source_fails_closed(tmp_path):
    result, codes = _apply_single_content_placement(
        tmp_path,
        spec_overrides={
            "text": None,
            "source": {
                "name": "runtime-observed:/var/log/nginx/access.log",
                "version": "*",
                "build": None,
            },
        },
    )
    assert result.success is False
    assert "aptl.provisioner.content-placement-rejected" in codes
    assert any(
        "runtime-observed-source" in d.message
        for d in result.diagnostics
        if d.code == "aptl.provisioner.content-placement-rejected"
    )


def test_content_placement_source_path_escape_fails_closed(tmp_path):
    result, codes = _apply_single_content_placement(
        tmp_path,
        spec_overrides={
            "text": None,
            "source": {"name": "../../../etc/passwd", "version": "*", "build": None},
        },
    )
    assert result.success is False
    assert "aptl.provisioner.content-placement-rejected" in codes
    assert any(
        "source-path-escapes-project" in d.message
        for d in result.diagnostics
        if d.code == "aptl.provisioner.content-placement-rejected"
    )


def test_content_placement_destination_without_backing_mount_fails_closed(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _fileshare_and_ad_compose(tmp_path)
    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    kali_node = _node_resource("scenario.kali")
    content = _content_resource(
        target_node="scenario.kali", target_address=kali_node.address
    )
    result = provisioner.apply(
        _plan_for_resources(kali_node, content), RuntimeSnapshot()
    )
    codes = {d.code for d in result.diagnostics}
    assert result.success is False
    assert "aptl.provisioner.content-placement-rejected" in codes
    assert any(
        "destination-without-backing-mount" in d.message
        for d in result.diagnostics
        if d.code == "aptl.provisioner.content-placement-rejected"
    )


def test_account_placement_target_without_provisioner_fails_closed(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _fileshare_and_ad_compose(tmp_path)
    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
    provisioner = AptlProvisioner(
        project_dir=tmp_path,
        config=AptlConfig(lab={"name": "test"}),
        deployment_backend=backend,
    )
    kali_node = _node_resource("scenario.kali")
    account = _account_resource(
        node_name="scenario.kali", target_address=kali_node.address
    )
    result = provisioner.apply(
        _plan_for_resources(kali_node, account), RuntimeSnapshot()
    )
    codes = {d.code for d in result.diagnostics}
    assert result.success is False
    assert "aptl.provisioner.account-placement-rejected" in codes
    assert any(
        "no-account-provisioner-for-target" in d.message
        for d in result.diagnostics
        if d.code == "aptl.provisioner.account-placement-rejected"
    )


def test_provisioner_rejects_unsupported_resource_type(tmp_path):
    from aptl.backends.aces import AptlProvisioner

    _write_compose(tmp_path, {"kali": ["kali"]})
    backend = MagicMock()
    backend.realize.return_value = LabResult(success=True, message="ok")
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
    backend.realize.assert_not_called()


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
    backend.realize.return_value = LabResult(success=True, message="ok")
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


def test_apply_provisioning_fails_closed_on_vacuous_realization_snapshot():
    """Exact SEM-218 requirements must not pass on an empty returned snapshot."""
    from unittest.mock import MagicMock as _MagicMock

    from aces_contracts.runtime_state import OperationState

    from aptl.backends.aces import _apply_provisioning_and_orchestration

    execution_plan = _execution_plan_with_realization_requirements()

    receipt = _MagicMock()
    receipt.operation_id = "op-prov"
    op_status = _MagicMock()
    op_status.state = OperationState.SUCCEEDED
    op_status.diagnostics = []

    mock_cp = _MagicMock()
    mock_cp.submit_provisioning.return_value = receipt
    mock_cp.get_operation.return_value = op_status
    mock_cp.snapshot = RuntimeSnapshot()

    mock_target = _MagicMock()
    mock_target.orchestrator = None
    mock_target.evaluator = None
    mock_target.provisioner = None

    failure, _, _ = _apply_provisioning_and_orchestration(
        mock_cp, execution_plan, mock_target
    )

    assert failure is not None
    assert failure.success is False
    assert "runtime.backend-contract-invalid" in (failure.error or "")


def test_apply_provisioning_records_realization_provenance_when_honored():
    """Honored exact requirements are disclosed on the runtime snapshot."""
    from unittest.mock import MagicMock as _MagicMock

    from aces_contracts.runtime_state import OperationState, SnapshotEntry

    from aptl.backends.aces import _apply_provisioning_and_orchestration

    execution_plan = _execution_plan_with_realization_requirements()
    resource = next(iter(execution_plan.provisioning.resources.values()))
    snapshot = RuntimeSnapshot(
        entries={
            resource.address: SnapshotEntry(
                address=resource.address,
                domain=resource.domain,
                resource_type=resource.resource_type,
                payload=resource.payload,
            )
        }
    )

    receipt = _MagicMock()
    receipt.operation_id = "op-prov"
    op_status = _MagicMock()
    op_status.state = OperationState.SUCCEEDED
    op_status.diagnostics = []

    mock_cp = _MagicMock()
    mock_cp.submit_provisioning.return_value = receipt
    mock_cp.get_operation.return_value = op_status
    mock_cp.snapshot = snapshot

    mock_target = _MagicMock()
    mock_target.orchestrator = None
    mock_target.evaluator = None
    mock_target.provisioner = None

    failure, _, _ = _apply_provisioning_and_orchestration(
        mock_cp, execution_plan, mock_target
    )

    assert failure is None
    kinds = {
        entry.requirement_kind
        for entry in mock_cp.snapshot.realization_provenance
    }
    assert {"node-type", "os-family"} <= kinds
