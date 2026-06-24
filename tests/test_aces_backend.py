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
                lines.extend([f"      {dependency}:", "        condition: service_started"])
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


def _otel_only_config() -> AptlConfig:
    return AptlConfig(
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


def _node_resource_with_health(node_name: str, status: str) -> PlannedResource:
    # ACES carries the SDL ``runtime.health`` declaration into the compiled node
    # payload at ``spec.node.runtime.health`` (verified against a real compile).
    resource = _node_resource(node_name)
    resource.payload["spec"]["node"]["runtime"] = {
        "health": {
            "status": status,
            "description": "Compose healthcheck must pass before startup is ready.",
        }
    }
    return resource


def test_realization_extracts_declared_node_health(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"aptl-otel-collector": ["otel"]})

    realization = interpret_provisioning_plan(
        plan=_plan_for_resources(
            _node_resource_with_health("aptl-otel-collector", "healthy")
        ),
        project_dir=tmp_path,
        config=_otel_only_config(),
    )

    node = realization.nodes[0]
    assert node.declared_health == "healthy"
    assert node.details()["declared_health"] == "healthy"


def test_realization_declared_health_absent_when_undeclared(tmp_path):
    from aptl.backends.aces_realization import interpret_provisioning_plan

    _write_compose(tmp_path, {"aptl-otel-collector": ["otel"]})

    realization = interpret_provisioning_plan(
        plan=_plan_for_nodes("aptl-otel-collector"),
        project_dir=tmp_path,
        config=_otel_only_config(),
    )

    node = realization.nodes[0]
    assert node.declared_health is None
    assert node.details()["declared_health"] is None


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
        "operation-receipt-v1",
        "operation-status-v1",
        "runtime-snapshot-v1",
        "workflow-result-envelope-v1",
        "workflow-history-event-stream-v1",
        "evaluation-result-envelope-v1",
        "evaluation-history-event-stream-v1",
    }
    assert required <= set(payload["supported_contract_versions"])
    # orchestration-evaluation: orchestrator + evaluator declared; participant
    # runtime remains out of scope.
    assert manifest.has_orchestrator is True
    assert manifest.has_evaluator is True
    assert manifest.has_participant_runtime is False


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

    assert result.success is True
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

    assert result.success is True
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
    return aces_plan(compile_runtime_model(scenario), create_aptl_manifest()).orchestration


def test_start_aces_scenario_submits_orchestration_for_workflow_scenario(mocker, tmp_path):
    """A scenario carrying workflows routes through the control plane's
    orchestration submission (not just provisioning), and the lab still starts."""
    from aces_contracts.runtime_state import OperationState

    from aptl.backends import aces

    _write_compose(tmp_path, {"victim": ["victim"]})
    mocker.patch("aptl.backends.aces.parse_sdl_file", return_value=object())
    orchestration = _workflow_orchestration_plan()
    assert orchestration.actionable_operations  # guard: the plan really carries workflows

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

    assert result.success is True
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

    assert result.success is False
    assert result.error


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

    assert result.success is False
    assert result.error


def test_start_aces_scenario_submits_evaluation_for_objective_scenario(mocker, tmp_path):
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

    assert result.success is True
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

    class FakeRuntimeManager:
        def __init__(self, target):
            self.target = target

        def plan(self, parsed_scenario):
            return _FakeExecutionPlan(
                _plan_for_nodes("techvault.victim"),
                orchestration=orchestration,
            )

    def fake_create_target(*, project_dir, config, backend):
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
        )
        return target

    mocker.patch("aptl.backends.aces.RuntimeManager", FakeRuntimeManager)
    mocker.patch("aptl.backends.aces.RuntimeControlPlane", FakeControlPlane)
    mocker.patch("aptl.backends.aces.create_aptl_runtime_target", fake_create_target)
    backend = MagicMock()
    backend.start.return_value = LabResult(success=True, message="ok")
    config = AptlConfig(lab={"name": "test"}, containers={"victim": True})

    result = aces.start_aces_scenario(tmp_path, config, backend)

    assert result.success is True
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

    assert result.success is False
    assert result.error
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

    assert result.success is False
    assert result.error
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
    attacker.payload["spec"]["runtime"] = {
        "rendered_configs": ["kali-operator.conf"],
        "evidence_paths": ["runs/exercise-a/kali"],
    }
    target = _node_resource("exercise-b.victim")
    target.payload["spec"]["node"]["services"] = [
        {"name": "web-target", "port": 8080, "protocol": "tcp"}
    ]
    target.payload["spec"]["runtime"] = {
        "rendered_configs": ["victim-web.conf"],
        "evidence_paths": ["runs/exercise-b/victim"],
    }

    first = provisioner.apply(_plan_for_resources(attacker), RuntimeSnapshot())
    second = provisioner.apply(_plan_for_resources(target), RuntimeSnapshot())

    assert first.success is True
    assert second.success is True
    assert (
        first.details["realization"]["nodes"] != second.details["realization"]["nodes"]
    )
    assert first.details["realization"]["nodes"][0]["services"] == ["ssh-control"]
    assert second.details["realization"]["nodes"][0]["services"] == ["web-target"]
    assert first.details["realization"]["nodes"][0]["rendered_configs"] == [
        "kali-operator.conf"
    ]
    assert second.details["realization"]["nodes"][0]["rendered_configs"] == [
        "victim-web.conf"
    ]


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
