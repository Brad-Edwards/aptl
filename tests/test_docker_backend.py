"""Integration tests for the Docker backend with the ssh-lateral-movement scenario.

Tests the full SDL -> compile -> plan -> execute pipeline using Docker
containers. Validates that the scenario DSL, runtime SDK, and Docker backend
work end-to-end.

Requires Docker daemon running. Tests are skipped if Docker is unavailable.
"""

import subprocess
from pathlib import Path

import pytest

from aptl.core.sdl import parse_sdl_file
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.planner import plan
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.models import RuntimeSnapshot
from aptl.backends.docker import (
    DockerProvisioner,
    DockerOrchestrator,
    DockerEvaluator,
    create_docker_manifest,
    create_docker_target,
)
from aptl.backends import get_backend_registry


SCENARIO_PATH = Path(__file__).resolve().parents[1] / "scenarios" / "ssh-lateral-movement.sdl.yaml"


def _docker_available() -> bool:
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
    reason="Docker daemon not available",
)


# ---------------------------------------------------------------------------
# Unit tests (no Docker needed)
# ---------------------------------------------------------------------------


class TestScenarioParsing:
    """Validate the SDL scenario parses and validates correctly."""

    def test_parse_scenario(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert scenario.name == "ssh-lateral-movement"
        assert scenario.semantic_validated is True
        assert scenario.advisories == []

    def test_scenario_nodes(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert "lab-net" in scenario.nodes
        assert "server" in scenario.nodes
        assert "workstation" in scenario.nodes
        assert "kali" in scenario.nodes
        assert scenario.nodes["lab-net"].type.value == "switch"
        assert scenario.nodes["server"].type.value == "vm"
        assert str(scenario.nodes["server"].os) == "OSFamily.LINUX"

    def test_scenario_accounts(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert "server-admin" in scenario.accounts
        assert "workstation-admin" in scenario.accounts
        assert "kali-operator" in scenario.accounts
        assert scenario.accounts["server-admin"].password_strength.value == "weak"
        assert scenario.accounts["server-admin"].node == "server"

    def test_scenario_content(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert "server-flag" in scenario.content
        assert "workstation-flag" in scenario.content
        assert scenario.content["server-flag"].text == "FLAG{server-alpha-9f3c}"
        assert scenario.content["server-flag"].target == "server"

    def test_scenario_agents(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert "red-agent" in scenario.agents
        agent = scenario.agents["red-agent"]
        assert agent.entity == "red-team"
        assert "kali-operator" in agent.starting_accounts
        assert "ssh-brute-force" in agent.actions

    def test_scenario_objectives(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert "capture-server-flag" in scenario.objectives
        assert "capture-workstation-flag" in scenario.objectives
        obj = scenario.objectives["capture-workstation-flag"]
        assert "capture-server-flag" in obj.depends_on

    def test_scenario_workflow(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        wf = scenario.workflows["attack-workflow"]
        assert wf.start == "capture-server"
        assert wf.timeout is not None
        assert wf.timeout.seconds == 600
        assert "capture-server" in wf.steps
        assert "capture-workstation" in wf.steps
        assert "done" in wf.steps
        assert "fail" in wf.steps

    def test_scenario_vulnerabilities(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert "weak-admin-password" in scenario.vulnerabilities
        vuln = scenario.vulnerabilities["weak-admin-password"]
        assert vuln.vuln_class == "CWE-521"

    def test_scenario_relationships(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert "server-auth" in scenario.relationships
        assert "kali-to-server" in scenario.relationships
        assert scenario.relationships["server-auth"].type.value == "authenticates_with"


class TestCompileAndPlan:
    """Validate the scenario compiles and plans correctly."""

    def test_compile(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        model = compile_runtime_model(scenario)
        assert model.scenario_name == "ssh-lateral-movement"
        assert "provision.network.lab-net" in model.networks
        assert "provision.node.server" in model.node_deployments
        assert "provision.node.workstation" in model.node_deployments
        assert "provision.node.kali" in model.node_deployments
        assert "provision.content.server-flag" in model.content_placements
        assert "provision.content.workstation-flag" in model.content_placements
        assert "provision.account.server-admin" in model.account_placements
        assert "orchestration.workflow.attack-workflow" in model.workflows
        assert model.diagnostics == []

    def test_plan_with_docker_manifest(self):
        scenario = parse_sdl_file(SCENARIO_PATH)
        model = compile_runtime_model(scenario)
        manifest = create_docker_manifest()
        execution_plan = plan(model, manifest)
        assert execution_plan.is_valid
        assert len(execution_plan.provisioning.operations) > 0
        assert len(execution_plan.orchestration.operations) > 0
        assert len(execution_plan.evaluation.operations) > 0


class TestDockerManifest:
    """Validate the Docker backend manifest declares correct capabilities."""

    def test_manifest_structure(self):
        manifest = create_docker_manifest()
        assert manifest.name == "docker"
        assert manifest.has_orchestrator is True
        assert manifest.has_evaluator is True

    def test_provisioner_capabilities(self):
        manifest = create_docker_manifest()
        prov = manifest.provisioner
        assert "vm" in prov.supported_node_types
        assert "switch" in prov.supported_node_types
        assert "linux" in prov.supported_os_families
        assert prov.supports_accounts is True
        assert prov.max_total_nodes == 20

    def test_target_construction(self):
        target = create_docker_target()
        assert target.name == "docker"
        assert target.provisioner is not None
        assert target.orchestrator is not None
        assert target.evaluator is not None


class TestBackendRegistry:
    """Validate the Docker backend is registered and accessible."""

    def test_docker_registered(self):
        registry = get_backend_registry()
        assert registry.is_registered("docker")
        assert "docker" in registry.list_backends()

    def test_create_from_registry(self):
        registry = get_backend_registry()
        target = registry.create("docker")
        assert target.name == "docker"
        assert target.manifest.provisioner.name == "docker-provisioner"


# ---------------------------------------------------------------------------
# Docker integration tests
# ---------------------------------------------------------------------------


@requires_docker
class TestDockerIntegration:
    """Full end-to-end execution with Docker containers."""

    def test_full_pipeline(self):
        """Parse, compile, plan, provision, orchestrate, and evaluate."""
        # 1. Parse and validate scenario
        scenario = parse_sdl_file(SCENARIO_PATH)
        assert scenario.semantic_validated

        # 2. Compile to runtime model
        model = compile_runtime_model(scenario)
        assert model.diagnostics == []

        # 3. Create Docker target and plan
        target = create_docker_target(project_prefix="aptl-test")
        execution_plan = plan(model, target.manifest)
        assert execution_plan.is_valid, (
            f"Plan diagnostics: {execution_plan.diagnostics}"
        )

        # 4. Execute through the control plane
        control_plane = RuntimeControlPlane(target)

        try:
            # Provision
            prov_receipt = control_plane.submit_provisioning(
                execution_plan.provisioning
            )
            assert prov_receipt.accepted, (
                f"Provisioning rejected: {prov_receipt.diagnostics}"
            )

            # Verify containers were created
            provisioner = target.provisioner
            assert isinstance(provisioner, DockerProvisioner)
            containers = provisioner.containers
            networks = provisioner.networks
            assert len(networks) >= 1, "Expected at least 1 Docker network"
            assert len(containers) >= 3, "Expected at least 3 containers"

            # Orchestrate
            orch_receipt = control_plane.submit_orchestration(
                execution_plan.orchestration
            )
            assert orch_receipt.accepted

            # Evaluate
            eval_receipt = control_plane.submit_evaluation(
                execution_plan.evaluation
            )
            assert eval_receipt.accepted

            # Check snapshot state
            snapshot = control_plane.snapshot
            assert len(snapshot.entries) > 0

            # Verify provisioning entries exist
            prov_entries = snapshot.for_domain(
                __import__("aptl.core.runtime.models", fromlist=["RuntimeDomain"]).RuntimeDomain.PROVISIONING
            )
            assert "provision.network.lab-net" in prov_entries
            assert "provision.node.server" in prov_entries
            assert "provision.node.workstation" in prov_entries
            assert "provision.node.kali" in prov_entries

            # Verify workflow state
            orch_results = snapshot.orchestration_results
            wf_key = "orchestration.workflow.attack-workflow"
            assert wf_key in orch_results
            wf_state = orch_results[wf_key]
            assert wf_state["workflow_status"] == "running"
            assert wf_state["run_id"] == f"{wf_key}-run"

            # Verify evaluation results exist
            assert len(snapshot.evaluation_results) > 0

            # Test timeout reconciliation
            timeout_receipt = control_plane.reconcile_workflow_timeouts()
            assert timeout_receipt.accepted

        finally:
            # Cleanup Docker resources
            if isinstance(target.provisioner, DockerProvisioner):
                target.provisioner.cleanup()

    def test_provisioner_cleanup(self):
        """Verify cleanup removes all Docker resources."""
        provisioner = DockerProvisioner(project_prefix="aptl-cleanup-test")

        # Create a test network
        from aptl.core.runtime.models import (
            ProvisioningPlan,
            ProvisionOp,
            ChangeAction,
            RuntimeSnapshot,
            PlannedResource,
            RuntimeDomain,
        )

        test_plan = ProvisioningPlan(
            resources={
                "provision.network.test-net": PlannedResource(
                    address="provision.network.test-net",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="network",
                    payload={
                        "spec": {
                            "properties": {
                                "cidr": "172.30.0.0/24",
                                "gateway": "172.30.0.1",
                            }
                        }
                    },
                ),
            },
            operations=[
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.network.test-net",
                    resource_type="network",
                    payload={
                        "spec": {
                            "properties": {
                                "cidr": "172.30.0.0/24",
                                "gateway": "172.30.0.1",
                            }
                        }
                    },
                ),
            ],
        )

        try:
            result = provisioner.apply(test_plan, RuntimeSnapshot())
            assert result.success
            assert len(provisioner.networks) == 1
        finally:
            provisioner.cleanup()
            assert len(provisioner.networks) == 0
            assert len(provisioner.containers) == 0
