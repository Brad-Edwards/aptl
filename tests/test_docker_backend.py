"""Tests for the honest Docker reference backend."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from aptl.backends import get_backend_registry
from aptl.backends.docker import (
    DockerProvisioner,
    create_docker_manifest,
    create_docker_target,
)
from aptl.core.runtime.capabilities import WorkflowFeature
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.models import (
    ChangeAction,
    OperationState,
    PlannedResource,
    ProvisionOp,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeSnapshot,
)
from aptl.core.runtime.planner import plan
from aptl.core.sdl import parse_sdl_file


SCENARIO_PATH = (
    Path(__file__).resolve().parents[1] / "scenarios" / "reference-web-service.sdl.yaml"
)


def _docker_available() -> bool:
    if importlib.util.find_spec("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker daemon or Python docker package not available",
)


@pytest.fixture(scope="module")
def scenario():
    return parse_sdl_file(SCENARIO_PATH)


@pytest.fixture(scope="module")
def compiled_model(scenario):
    return compile_runtime_model(scenario)


@pytest.fixture(scope="module")
def manifest():
    return create_docker_manifest()


@pytest.fixture(scope="module")
def execution_plan(compiled_model, manifest):
    result = plan(compiled_model, manifest)
    assert result.is_valid, [diag.message for diag in result.diagnostics]
    return result


class TestReferenceScenario:
    def test_reference_scenario_parses_cleanly(self, scenario):
        assert scenario.name == "reference-web-service"
        assert scenario.semantic_validated is True
        assert scenario.advisories == []

    def test_reference_scenario_exercises_the_supported_subset(self, scenario):
        assert {"service-net", "web", "operator"} <= set(scenario.nodes)
        assert "http-service" in scenario.features
        assert {"web-http-listening", "web-index-served"} <= set(scenario.conditions)
        assert {"web-admin", "operator-account"} <= set(scenario.accounts)
        assert {"reference-index", "operator-notes"} <= set(scenario.content)
        assert {"exercise-control", "platform-team"} <= set(scenario.entities)
        assert "verifier-agent" in scenario.agents
        assert len(scenario.relationships) == 2
        assert len(scenario.metrics) == 2
        assert len(scenario.evaluations) == 1
        assert len(scenario.tlos) == 1
        assert len(scenario.goals) == 1
        assert len(scenario.injects) == 1
        assert len(scenario.events) == 1
        assert len(scenario.scripts) == 1
        assert len(scenario.stories) == 1
        assert {"verify-web-service", "verify-web-content"} <= set(scenario.objectives)
        assert "reference-validation" in scenario.workflows


class TestCompileAndPlan:
    def test_compiles_without_diagnostics(self, compiled_model):
        assert compiled_model.diagnostics == []
        assert "provision.network.service-net" in compiled_model.networks
        assert "provision.node.web" in compiled_model.node_deployments
        assert "provision.node.operator" in compiled_model.node_deployments
        assert "provision.feature.web.http-service" in compiled_model.feature_bindings
        assert "evaluation.condition.web.web-http-listening" in compiled_model.condition_bindings
        assert "evaluation.metric.web-http-availability" in compiled_model.metrics
        assert "evaluation.objective.verify-web-service" in compiled_model.objectives
        assert "orchestration.workflow.reference-validation" in compiled_model.workflows

    def test_plans_cleanly_against_the_honest_manifest(self, execution_plan):
        assert execution_plan.is_valid
        assert len(execution_plan.provisioning.actionable_operations) > 0
        assert len(execution_plan.evaluation.actionable_operations) > 0
        assert len(execution_plan.orchestration.actionable_operations) > 0


class TestDockerManifest:
    def test_manifest_matches_the_supported_slice(self, manifest):
        assert manifest.name == "docker"
        assert manifest.provisioner.supported_node_types == frozenset({"vm", "switch"})
        assert manifest.provisioner.supported_os_families == frozenset({"linux"})
        assert manifest.provisioner.supported_content_types == frozenset({"file", "directory"})
        assert manifest.provisioner.supports_accounts is True
        assert manifest.provisioner.constraints["feature_bindings"] == "http-service only"

        assert manifest.orchestrator is not None
        assert manifest.orchestrator.supported_sections == frozenset(
            {"injects", "events", "scripts", "stories", "workflows"}
        )
        assert manifest.orchestrator.supports_workflows is True
        assert manifest.orchestrator.supports_condition_refs is True
        assert manifest.orchestrator.supports_inject_bindings is False
        assert manifest.orchestrator.supported_workflow_features == frozenset(
            {
                WorkflowFeature.TIMEOUTS,
                WorkflowFeature.FAILURE_TRANSITIONS,
                WorkflowFeature.DECISION,
            }
        )

        assert manifest.evaluator is not None
        assert manifest.evaluator.supported_sections == frozenset(
            {"conditions", "metrics", "evaluations", "tlos", "goals", "objectives"}
        )
        assert manifest.evaluator.supports_scoring is True
        assert manifest.evaluator.supports_objectives is True
        assert manifest.evaluator.constraints["metric_types"] == "conditional metrics only"

    def test_target_creation_rejects_raw_scenario_side_channels(self):
        with pytest.raises(ValueError, match="raw SDL scenario payloads"):
            create_docker_target(scenario={"name": "legacy-side-channel"})

    def test_backend_registry_exposes_docker(self):
        registry = get_backend_registry()
        assert registry.is_registered("docker")
        target = registry.create("docker")
        assert target.name == "docker"
        assert target.manifest.name == "docker"


class TestRuntimeContractBehavior:
    def test_orchestration_requires_evaluated_state(self, execution_plan):
        target = create_docker_target(project_prefix="aptl-orch-only")
        control_plane = RuntimeControlPlane(target)

        receipt = control_plane.submit_orchestration(execution_plan.orchestration)
        assert receipt.accepted is True

        status = control_plane.get_operation(receipt.operation_id)
        assert status is not None
        assert status.state == OperationState.FAILED
        assert any(diag.code.startswith("docker.workflow-objective") for diag in status.diagnostics)

        workflow_result = control_plane.snapshot.orchestration_results[
            "orchestration.workflow.reference-validation"
        ]
        assert workflow_result["workflow_status"] == "failed"

    def test_provisioner_stops_after_compose_failure(self, monkeypatch):
        provisioner = DockerProvisioner(project_prefix="aptl-compose-fail")
        create_calls: list[str] = []

        def fake_compose_up(_ops):
            raise RuntimeError("compose boom")

        def fake_create_resource(address, resource_type, payload):
            create_calls.append(address)

        monkeypatch.setattr(provisioner, "_compose_up", fake_compose_up)
        monkeypatch.setattr(provisioner, "_create_resource", fake_create_resource)

        plan = ProvisioningPlan(
            resources={
                "provision.network.service-net": PlannedResource(
                    address="provision.network.service-net",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="network",
                    payload={"spec": {"properties": {"cidr": "10.77.0.0/24", "gateway": "10.77.0.1"}}},
                ),
                "provision.node.web": PlannedResource(
                    address="provision.node.web",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="node",
                    payload={
                        "node_name": "web",
                        "os_family": "linux",
                        "spec": {"source": {"name": "ubuntu", "version": "22.04"}},
                    },
                    ordering_dependencies=("provision.network.service-net",),
                ),
                "provision.content.reference-index": PlannedResource(
                    address="provision.content.reference-index",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="content-placement",
                    payload={
                        "target_node": "web",
                        "target_address": "provision.node.web",
                        "spec": {
                            "type": "file",
                            "path": "/srv/reference-site/index.html",
                            "text": "ACES Reference Service Ready",
                        },
                    },
                    ordering_dependencies=("provision.node.web",),
                ),
            },
            operations=[
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.network.service-net",
                    resource_type="network",
                    payload={"spec": {"properties": {"cidr": "10.77.0.0/24", "gateway": "10.77.0.1"}}},
                ),
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.node.web",
                    resource_type="node",
                    payload={
                        "node_name": "web",
                        "os_family": "linux",
                        "spec": {"source": {"name": "ubuntu", "version": "22.04"}},
                    },
                    ordering_dependencies=("provision.network.service-net",),
                ),
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.content.reference-index",
                    resource_type="content-placement",
                    payload={
                        "target_node": "web",
                        "target_address": "provision.node.web",
                        "spec": {
                            "type": "file",
                            "path": "/srv/reference-site/index.html",
                            "text": "ACES Reference Service Ready",
                        },
                    },
                    ordering_dependencies=("provision.node.web",),
                ),
            ],
        )

        result = provisioner.apply(plan, RuntimeSnapshot())
        assert result.success is False
        assert create_calls == []
        assert "provision.content.reference-index" not in result.snapshot.entries


@requires_docker
class TestDockerIntegration:
    def test_provisioning_creates_the_reference_environment(self, execution_plan):
        target = create_docker_target(project_prefix="aptl-ref-provision")
        control_plane = RuntimeControlPlane(target)
        provisioner = target.provisioner
        assert isinstance(provisioner, DockerProvisioner)

        try:
            receipt = control_plane.submit_provisioning(execution_plan.provisioning)
            assert receipt.accepted is True

            status = control_plane.get_operation(receipt.operation_id)
            assert status is not None
            assert status.state == OperationState.SUCCEEDED, status.diagnostics

            assert len(provisioner.networks) == 1
            assert len(provisioner.containers) == 2

            web_cid = provisioner.container_for_node("web")
            operator_cid = provisioner.container_for_node("operator")
            assert web_cid is not None
            assert operator_cid is not None

            http_check = subprocess.run(
                [
                    "docker",
                    "exec",
                    web_cid,
                    "python3",
                    "-c",
                    (
                        "import sys, urllib.request; "
                        "body = urllib.request.urlopen('http://127.0.0.1/').read().decode('utf-8').strip(); "
                        "sys.exit(0 if body == 'ACES Reference Service Ready' else 1)"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            assert http_check.returncode == 0, http_check.stderr or http_check.stdout

            account_check = subprocess.run(
                ["docker", "exec", web_cid, "id", "webadmin"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            assert account_check.returncode == 0, account_check.stderr

            directory_check = subprocess.run(
                ["docker", "exec", operator_cid, "test", "-d", "/home/operator/reference-data"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            assert directory_check.returncode == 0, directory_check.stderr
        finally:
            provisioner.cleanup()

    def test_full_reference_pipeline_works_through_runtime_affordances(self, execution_plan):
        target = create_docker_target(project_prefix="aptl-ref-e2e")
        control_plane = RuntimeControlPlane(target)
        provisioner = target.provisioner
        assert isinstance(provisioner, DockerProvisioner)

        try:
            provision_receipt = control_plane.submit_provisioning(execution_plan.provisioning)
            assert provision_receipt.accepted is True
            provision_status = control_plane.get_operation(provision_receipt.operation_id)
            assert provision_status is not None
            assert provision_status.state == OperationState.SUCCEEDED, provision_status.diagnostics

            evaluation_receipt = control_plane.submit_evaluation(execution_plan.evaluation)
            assert evaluation_receipt.accepted is True
            evaluation_status = control_plane.get_operation(evaluation_receipt.operation_id)
            assert evaluation_status is not None
            assert evaluation_status.state == OperationState.SUCCEEDED, evaluation_status.diagnostics

            orchestration_receipt = control_plane.submit_orchestration(execution_plan.orchestration)
            assert orchestration_receipt.accepted is True
            orchestration_status = control_plane.get_operation(orchestration_receipt.operation_id)
            assert orchestration_status is not None
            assert orchestration_status.state == OperationState.SUCCEEDED, orchestration_status.diagnostics

            snapshot = control_plane.snapshot

            provision_entries = snapshot.for_domain(RuntimeDomain.PROVISIONING)
            orchestration_entries = snapshot.for_domain(RuntimeDomain.ORCHESTRATION)
            evaluation_entries = snapshot.for_domain(RuntimeDomain.EVALUATION)
            assert "provision.network.service-net" in provision_entries
            assert "provision.node.web" in provision_entries
            assert "provision.node.operator" in provision_entries
            assert "orchestration.workflow.reference-validation" in orchestration_entries
            assert "evaluation.objective.verify-web-content" in evaluation_entries

            condition_result = snapshot.evaluation_results["evaluation.condition.web.web-http-listening"]
            assert condition_result["status"] == "ready"
            assert condition_result["passed"] is True

            content_condition_result = snapshot.evaluation_results["evaluation.condition.web.web-index-served"]
            assert content_condition_result["status"] == "ready"
            assert content_condition_result["passed"] is True

            availability_metric = snapshot.evaluation_results["evaluation.metric.web-http-availability"]
            assert availability_metric["status"] == "ready"
            assert availability_metric["score"] == 50
            assert availability_metric["max_score"] == 50

            fidelity_metric = snapshot.evaluation_results["evaluation.metric.web-content-fidelity"]
            assert fidelity_metric["status"] == "ready"
            assert fidelity_metric["score"] == 50
            assert fidelity_metric["max_score"] == 50

            evaluation_result = snapshot.evaluation_results["evaluation.evaluation.reference-service-health"]
            assert evaluation_result["status"] == "ready"
            assert evaluation_result["passed"] is True

            goal_result = snapshot.evaluation_results["evaluation.goal.platform-validation-goal"]
            assert goal_result["status"] == "ready"
            assert goal_result["passed"] is True

            service_objective = snapshot.evaluation_results["evaluation.objective.verify-web-service"]
            assert service_objective["status"] == "ready"
            assert service_objective["passed"] is True

            content_objective = snapshot.evaluation_results["evaluation.objective.verify-web-content"]
            assert content_objective["status"] == "ready"
            assert content_objective["passed"] is True

            workflow_result = snapshot.orchestration_results["orchestration.workflow.reference-validation"]
            assert workflow_result["workflow_status"] == "succeeded"
            assert workflow_result["terminal_reason"] == "Reference validation completed"
            assert workflow_result["steps"]["verify-service"]["lifecycle"] == "completed"
            assert workflow_result["steps"]["verify-service"]["outcome"] == "succeeded"
            assert workflow_result["steps"]["verify-service"]["attempts"] == 1
            assert workflow_result["steps"]["verify-content"]["lifecycle"] == "completed"
            assert workflow_result["steps"]["verify-content"]["outcome"] == "succeeded"
            assert workflow_result["steps"]["verify-content"]["attempts"] == 1

            workflow_history = snapshot.orchestration_history["orchestration.workflow.reference-validation"]
            assert workflow_history[0]["event_type"] == "workflow_started"
            assert workflow_history[-1]["event_type"] == "workflow_completed"
            completed_steps = [event for event in workflow_history if event["event_type"] == "step_completed"]
            assert {event["step_name"] for event in completed_steps} >= {"verify-service", "content-gate", "verify-content"}

            web_cid = provisioner.container_for_node("web")
            operator_cid = provisioner.container_for_node("operator")
            network_id = next(iter(provisioner.networks.values()))
            assert web_cid is not None
            assert operator_cid is not None
            network_inspect = subprocess.run(
                [
                    "docker",
                    "network",
                    "inspect",
                    network_id,
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            assert network_inspect.returncode == 0, network_inspect.stderr or network_inspect.stdout
            network_data = json.loads(network_inspect.stdout)
            attached = network_data[0].get("Containers", {})
            attached_ids = set(attached)
            assert web_cid in attached_ids
            assert operator_cid in attached_ids
        finally:
            provisioner.cleanup()
