"""Integration tests for the Docker backend with the ssh-lateral-movement scenario.

Tests the full SDL -> compile -> plan -> execute pipeline using Docker
containers. Validates that the scenario DSL, runtime SDK, and Docker backend
work end-to-end across all 21 SDL sections.

Requires Docker daemon running. Tests are skipped if Docker is unavailable.
"""

import subprocess
from pathlib import Path

import pytest

from aptl.core.sdl import parse_sdl_file
from aptl.core.runtime.compiler import compile_runtime_model
from aptl.core.runtime.planner import plan
from aptl.core.runtime.control_plane import RuntimeControlPlane
from aptl.core.runtime.models import RuntimeDomain, RuntimeSnapshot
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


@pytest.fixture(scope="module")
def scenario():
    return parse_sdl_file(SCENARIO_PATH)


@pytest.fixture(scope="module")
def compiled_model(scenario):
    return compile_runtime_model(scenario)


# ---------------------------------------------------------------------------
# SDL Parsing — all 21 sections
# ---------------------------------------------------------------------------


class TestScenarioParsing:
    """Validate the expanded SDL scenario parses and validates."""

    def test_parse_and_validate(self, scenario):
        assert scenario.name == "ssh-lateral-movement"
        assert scenario.semantic_validated is True
        assert scenario.advisories == []

    def test_nodes(self, scenario):
        assert "dmz-net" in scenario.nodes
        assert "internal-net" in scenario.nodes
        assert "server" in scenario.nodes
        assert "workstation" in scenario.nodes
        assert "kali" in scenario.nodes
        assert scenario.nodes["dmz-net"].type.value == "switch"
        assert scenario.nodes["server"].type.value == "vm"
        assert str(scenario.nodes["server"].os) == "OSFamily.LINUX"

    def test_infrastructure(self, scenario):
        assert "dmz-net" in scenario.infrastructure
        assert "internal-net" in scenario.infrastructure
        assert "server" in scenario.infrastructure
        infra_server = scenario.infrastructure["server"]
        assert "dmz-net" in infra_server.links
        assert "internal-net" in infra_server.links
        # workstation only on internal-net
        infra_ws = scenario.infrastructure["workstation"]
        assert "internal-net" in infra_ws.links
        assert "dmz-net" not in infra_ws.links
        # kali only on dmz-net with dependency on server
        infra_kali = scenario.infrastructure["kali"]
        assert "dmz-net" in infra_kali.links
        assert "server" in infra_kali.dependencies

    def test_variables(self, scenario):
        assert "exercise_speed" in scenario.variables
        assert "attack_timeout" in scenario.variables
        assert "weak_password" in scenario.variables
        speed = scenario.variables["exercise_speed"]
        assert speed.type.value == "number"
        assert speed.default == 1.0
        timeout = scenario.variables["attack_timeout"]
        assert timeout.type.value == "integer"
        assert timeout.default == 600

    def test_features(self, scenario):
        assert "ssh-password-auth" in scenario.features
        assert "http-service" in scenario.features
        assert "kali-tools" in scenario.features
        assert "sshd-config" in scenario.features
        assert "flag-permissions" in scenario.features
        # configuration type
        assert scenario.features["sshd-config"].type.value == "configuration"
        # dependency chain
        assert "ssh-password-auth" in scenario.features["sshd-config"].dependencies

    def test_vulnerabilities(self, scenario):
        assert "weak-admin-password" in scenario.vulnerabilities
        vuln = scenario.vulnerabilities["weak-admin-password"]
        assert vuln.vuln_class == "CWE-521"
        assert vuln.technical is True

    def test_conditions(self, scenario):
        assert "server-ssh-up" in scenario.conditions
        assert "server-http-up" in scenario.conditions
        assert "workstation-ssh-up" in scenario.conditions
        assert "brute-force-detected" in scenario.conditions
        assert "lateral-movement-detected" in scenario.conditions
        bf = scenario.conditions["brute-force-detected"]
        assert bf.command is not None
        assert bf.interval == 15

    def test_accounts(self, scenario):
        assert "server-admin" in scenario.accounts
        assert "workstation-admin" in scenario.accounts
        assert "kali-operator" in scenario.accounts
        assert scenario.accounts["server-admin"].password_strength.value == "weak"
        assert scenario.accounts["kali-operator"].password_strength.value == "strong"
        assert scenario.accounts["server-admin"].node == "server"

    def test_content(self, scenario):
        assert "server-flag" in scenario.content
        assert "workstation-flag" in scenario.content
        assert "server-credentials-file" in scenario.content
        assert "loot-directory" in scenario.content
        # File content
        assert scenario.content["server-flag"].text == "FLAG{server-alpha-9f3c}"
        assert scenario.content["server-flag"].type.value == "file"
        # Directory content
        assert scenario.content["loot-directory"].type.value == "directory"
        assert scenario.content["loot-directory"].destination == "/root/loot"
        # Tags
        assert "credentials" in scenario.content["server-credentials-file"].tags

    def test_entities(self, scenario):
        assert "white-cell" in scenario.entities
        assert "red-team" in scenario.entities
        assert "blue-team" in scenario.entities
        # Roles
        assert scenario.entities["white-cell"].role.value == "white"
        assert scenario.entities["red-team"].role.value == "red"
        assert scenario.entities["blue-team"].role.value == "blue"
        # Nested entities
        assert "operator" in scenario.entities["red-team"].entities
        assert "soc-analyst" in scenario.entities["blue-team"].entities
        assert "incident-responder" in scenario.entities["blue-team"].entities
        # Blue team TLOs
        assert "detect-brute-force" in scenario.entities["blue-team"].tlos

    def test_agents(self, scenario):
        assert "red-agent" in scenario.agents
        assert "blue-agent" in scenario.agents
        red = scenario.agents["red-agent"]
        blue = scenario.agents["blue-agent"]
        assert red.entity == "red-team"
        assert blue.entity == "blue-team"
        assert "ssh-brute-force" in red.actions
        assert "monitor-logs" in blue.actions
        assert "dmz-net" in red.allowed_subnets
        assert "internal-net" in blue.allowed_subnets

    def test_relationships(self, scenario):
        rels = scenario.relationships
        assert "server-auth" in rels
        assert "workstation-auth" in rels
        assert "kali-to-server" in rels
        assert "server-to-workstation" in rels
        assert "server-depends-on-dmz" in rels
        assert "blue-manages-server" in rels
        # Types
        assert rels["server-auth"].type.value == "authenticates_with"
        assert rels["kali-to-server"].type.value == "connects_to"
        assert rels["server-depends-on-dmz"].type.value == "depends_on"
        assert rels["blue-manages-server"].type.value == "manages"
        # Properties
        assert rels["server-auth"].properties["protocol"] == "ssh"

    # --- Scoring pipeline ---

    def test_metrics(self, scenario):
        metrics = scenario.metrics
        assert "red-server-flag" in metrics
        assert "red-workstation-flag" in metrics
        assert "blue-brute-detect" in metrics
        assert "blue-lateral-detect" in metrics
        assert "blue-ir-report" in metrics
        # Conditional metrics
        assert metrics["red-server-flag"].type.value == "conditional"
        assert metrics["red-server-flag"].max_score == 50
        assert metrics["red-server-flag"].condition == "server-ssh-up"
        # Manual metric
        assert metrics["blue-ir-report"].type.value == "manual"
        assert metrics["blue-ir-report"].artifact is True

    def test_evaluations(self, scenario):
        evals = scenario.evaluations
        assert "red-flag-capture" in evals
        assert "blue-detection-response" in evals
        assert "red-server-flag" in evals["red-flag-capture"].metrics
        assert evals["red-flag-capture"].min_score.percentage == 75
        assert evals["blue-detection-response"].min_score.percentage == 60

    def test_tlos(self, scenario):
        tlos = scenario.tlos
        assert "capture-all-flags" in tlos
        assert "detect-brute-force" in tlos
        assert "detect-lateral-movement" in tlos
        assert tlos["capture-all-flags"].evaluation == "red-flag-capture"

    def test_goals(self, scenario):
        goals = scenario.goals
        assert "red-team-goal" in goals
        assert "blue-team-goal" in goals
        assert "capture-all-flags" in goals["red-team-goal"].tlos
        assert len(goals["blue-team-goal"].tlos) == 2

    # --- Orchestration pipeline ---

    def test_injects(self, scenario):
        injects = scenario.injects
        assert "recon-intel" in injects
        assert "soc-briefing" in injects
        assert "escalation-notice" in injects
        assert injects["recon-intel"].from_entity == "white-cell"
        assert "red-team" in injects["recon-intel"].to_entities
        # Multi-target inject
        assert len(injects["escalation-notice"].to_entities) == 2

    def test_events(self, scenario):
        events = scenario.events
        assert "exercise-start" in events
        assert "brute-force-alert" in events
        assert "escalation-event" in events
        assert "recon-intel" in events["exercise-start"].injects
        assert "brute-force-detected" in events["brute-force-alert"].conditions

    def test_scripts(self, scenario):
        scripts = scenario.scripts
        assert "recon-phase" in scripts
        assert "attack-phase" in scripts
        assert "escalation-phase" in scripts
        assert scripts["recon-phase"].start_time == 0
        assert scripts["recon-phase"].end_time == 600  # 10 min in seconds
        assert scripts["attack-phase"].start_time == 600
        assert scripts["attack-phase"].end_time == 1800  # 30 min

    def test_stories(self, scenario):
        stories = scenario.stories
        assert "ctf-exercise" in stories
        assert len(stories["ctf-exercise"].scripts) == 3
        assert "recon-phase" in stories["ctf-exercise"].scripts

    # --- Objectives ---

    def test_objectives(self, scenario):
        objectives = scenario.objectives
        assert "capture-server-flag" in objectives
        assert "capture-workstation-flag" in objectives
        assert "detect-attack" in objectives
        # Red objectives
        assert objectives["capture-server-flag"].agent == "red-agent"
        assert "server-flag" in objectives["capture-server-flag"].targets
        # Blue objective with any_of mode
        detect = objectives["detect-attack"]
        assert detect.agent == "blue-agent"
        assert detect.success.mode.value == "any_of"
        # Dependency chain
        assert "capture-server-flag" in objectives["capture-workstation-flag"].depends_on

    # --- Workflows ---

    def test_workflows(self, scenario):
        workflows = scenario.workflows
        assert "attack-workflow" in workflows
        assert "detection-workflow" in workflows

    def test_attack_workflow_structure(self, scenario):
        wf = scenario.workflows["attack-workflow"]
        assert wf.start == "capture-server"
        steps = wf.steps
        assert "capture-server" in steps
        assert "check-detection" in steps
        assert "capture-workstation" in steps
        assert "capture-workstation-stealthy" in steps
        assert "done" in steps
        assert "fail" in steps

    def test_workflow_decision_step(self, scenario):
        step = scenario.workflows["attack-workflow"].steps["check-detection"]
        assert step.type.value == "decision"
        assert step.when is not None
        assert "brute-force-detected" in step.when.conditions
        assert step.then_step == "capture-workstation-stealthy"
        assert step.else_step == "capture-workstation"

    def test_workflow_retry_step(self, scenario):
        step = scenario.workflows["attack-workflow"].steps["capture-workstation-stealthy"]
        assert step.type.value == "retry"
        assert step.max_attempts == 3
        assert step.objective == "capture-workstation-flag"
        assert step.on_success == "done"
        assert step.on_exhausted == "fail"

    def test_detection_workflow(self, scenario):
        wf = scenario.workflows["detection-workflow"]
        assert wf.start == "monitor"
        assert "monitor" in wf.steps
        assert wf.steps["monitor"].objective == "detect-attack"


# ---------------------------------------------------------------------------
# Compile and Plan
# ---------------------------------------------------------------------------


class TestCompileAndPlan:
    """Validate the expanded scenario compiles and plans correctly."""

    def test_compile_no_diagnostics(self, compiled_model):
        assert compiled_model.diagnostics == []
        assert compiled_model.scenario_name == "ssh-lateral-movement"

    def test_compiled_networks(self, compiled_model):
        nets = compiled_model.networks
        assert "provision.network.dmz-net" in nets
        assert "provision.network.internal-net" in nets

    def test_compiled_nodes(self, compiled_model):
        nodes = compiled_model.node_deployments
        assert "provision.node.server" in nodes
        assert "provision.node.workstation" in nodes
        assert "provision.node.kali" in nodes

    def test_compiled_content(self, compiled_model):
        content = compiled_model.content_placements
        assert "provision.content.server-flag" in content
        assert "provision.content.workstation-flag" in content
        assert "provision.content.server-credentials-file" in content
        assert "provision.content.loot-directory" in content

    def test_compiled_accounts(self, compiled_model):
        accounts = compiled_model.account_placements
        assert "provision.account.server-admin" in accounts
        assert "provision.account.workstation-admin" in accounts
        assert "provision.account.kali-operator" in accounts

    def test_compiled_feature_bindings(self, compiled_model):
        features = compiled_model.feature_bindings
        assert len(features) >= 3  # ssh on server, ssh on ws, kali tools, http

    def test_compiled_condition_bindings(self, compiled_model):
        conditions = compiled_model.condition_bindings
        # server has: ssh-up, http-up, brute-force, lateral-movement
        # workstation has: ssh-up
        assert len(conditions) >= 5

    def test_compiled_scoring_pipeline(self, compiled_model):
        assert len(compiled_model.metrics) == 5
        assert len(compiled_model.evaluations) == 2
        assert len(compiled_model.tlos) == 3
        assert len(compiled_model.goals) == 2

    def test_compiled_orchestration(self, compiled_model):
        assert len(compiled_model.injects) >= 3
        assert len(compiled_model.events) == 3
        assert len(compiled_model.scripts) == 3
        assert len(compiled_model.stories) == 1

    def test_compiled_workflows(self, compiled_model):
        workflows = compiled_model.workflows
        assert "orchestration.workflow.attack-workflow" in workflows
        assert "orchestration.workflow.detection-workflow" in workflows
        atk = workflows["orchestration.workflow.attack-workflow"]
        assert atk.start_step == "capture-server"
        assert len(atk.control_steps) == 6  # 6 steps in attack workflow

    def test_compiled_objectives(self, compiled_model):
        objectives = compiled_model.objectives
        assert "evaluation.objective.capture-server-flag" in objectives
        assert "evaluation.objective.capture-workstation-flag" in objectives
        assert "evaluation.objective.detect-attack" in objectives

    def test_plan_valid(self, compiled_model):
        manifest = create_docker_manifest()
        execution_plan = plan(compiled_model, manifest)
        assert execution_plan.is_valid, (
            f"Plan diagnostics: {[d.message for d in execution_plan.diagnostics]}"
        )
        assert len(execution_plan.provisioning.operations) > 0
        assert len(execution_plan.orchestration.operations) > 0
        assert len(execution_plan.evaluation.operations) > 0

    def test_plan_operation_counts(self, compiled_model):
        manifest = create_docker_manifest()
        execution_plan = plan(compiled_model, manifest)
        # Should have substantial number of operations from the expanded scenario
        assert len(execution_plan.provisioning.operations) >= 15
        assert len(execution_plan.orchestration.operations) >= 10
        assert len(execution_plan.evaluation.operations) >= 15


# ---------------------------------------------------------------------------
# Docker Manifest
# ---------------------------------------------------------------------------


class TestDockerManifest:
    """Validate the expanded Docker backend manifest."""

    def test_manifest_name(self):
        manifest = create_docker_manifest()
        assert manifest.name == "docker"

    def test_provisioner_supports_directory(self):
        manifest = create_docker_manifest()
        assert "directory" in manifest.provisioner.supported_content_types
        assert "file" in manifest.provisioner.supported_content_types

    def test_orchestrator_supports_all_sections(self):
        manifest = create_docker_manifest()
        orch = manifest.orchestrator
        assert "injects" in orch.supported_sections
        assert "events" in orch.supported_sections
        assert "scripts" in orch.supported_sections
        assert "stories" in orch.supported_sections
        assert "workflows" in orch.supported_sections
        assert orch.supports_condition_refs is True
        assert orch.supports_inject_bindings is True

    def test_orchestrator_supports_workflow_features(self):
        from aptl.core.runtime.capabilities import WorkflowFeature
        manifest = create_docker_manifest()
        features = manifest.orchestrator.supported_workflow_features
        assert WorkflowFeature.TIMEOUTS in features
        assert WorkflowFeature.FAILURE_TRANSITIONS in features
        assert WorkflowFeature.DECISION in features
        assert WorkflowFeature.RETRY in features

    def test_evaluator_supports_scoring(self):
        manifest = create_docker_manifest()
        eval_caps = manifest.evaluator
        assert eval_caps.supports_scoring is True
        assert eval_caps.supports_objectives is True
        assert "conditions" in eval_caps.supported_sections
        assert "metrics" in eval_caps.supported_sections
        assert "evaluations" in eval_caps.supported_sections
        assert "tlos" in eval_caps.supported_sections
        assert "goals" in eval_caps.supported_sections

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


# ---------------------------------------------------------------------------
# Docker integration tests
# ---------------------------------------------------------------------------


@requires_docker
class TestDockerIntegration:
    """Full end-to-end execution with Docker containers."""

    def test_full_pipeline(self):
        """Parse, compile, plan, provision, orchestrate, and evaluate."""
        scenario = parse_sdl_file(SCENARIO_PATH)
        model = compile_runtime_model(scenario)
        assert model.diagnostics == []

        target = create_docker_target(project_prefix="aptl-test")
        execution_plan = plan(model, target.manifest)
        assert execution_plan.is_valid, (
            f"Plan diagnostics: {[d.message for d in execution_plan.diagnostics]}"
        )

        control_plane = RuntimeControlPlane(target)

        try:
            # Provision
            prov_receipt = control_plane.submit_provisioning(
                execution_plan.provisioning
            )
            assert prov_receipt.accepted, (
                f"Provisioning rejected: {prov_receipt.diagnostics}"
            )

            # Verify containers and networks were created
            provisioner = target.provisioner
            assert isinstance(provisioner, DockerProvisioner)
            assert len(provisioner.networks) >= 2, (
                "Expected at least 2 Docker networks (dmz + internal)"
            )
            assert len(provisioner.containers) >= 3, (
                "Expected at least 3 containers (server, workstation, kali)"
            )

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

            # Verify all three runtime domains have entries
            prov_entries = snapshot.for_domain(RuntimeDomain.PROVISIONING)
            orch_entries = snapshot.for_domain(RuntimeDomain.ORCHESTRATION)
            eval_entries = snapshot.for_domain(RuntimeDomain.EVALUATION)
            assert len(prov_entries) > 0, "Missing provisioning entries"
            assert len(orch_entries) > 0, "Missing orchestration entries"
            assert len(eval_entries) > 0, "Missing evaluation entries"

            # Verify provisioned resources
            assert "provision.network.dmz-net" in prov_entries
            assert "provision.network.internal-net" in prov_entries
            assert "provision.node.server" in prov_entries
            assert "provision.node.workstation" in prov_entries
            assert "provision.node.kali" in prov_entries

            # Verify both workflows running
            orch_results = snapshot.orchestration_results
            atk_key = "orchestration.workflow.attack-workflow"
            det_key = "orchestration.workflow.detection-workflow"
            assert atk_key in orch_results
            assert det_key in orch_results
            assert orch_results[atk_key]["workflow_status"] == "running"
            assert orch_results[det_key]["workflow_status"] == "running"

            # Verify evaluation results exist for scoring pipeline
            eval_results = snapshot.evaluation_results
            assert len(eval_results) > 0

            # Verify orchestration history
            orch_history = snapshot.orchestration_history
            assert atk_key in orch_history
            assert len(orch_history[atk_key]) >= 1

            # Verify evaluation history
            eval_history = snapshot.evaluation_history
            assert len(eval_history) > 0

            # Test timeout reconciliation
            timeout_receipt = control_plane.reconcile_workflow_timeouts()
            assert timeout_receipt.accepted

        finally:
            if isinstance(target.provisioner, DockerProvisioner):
                target.provisioner.cleanup()

    def test_directory_content_provisioning(self):
        """Verify directory content type creates directories in containers."""
        from aptl.core.runtime.models import (
            ProvisioningPlan,
            ProvisionOp,
            ChangeAction,
            PlannedResource,
        )

        provisioner = DockerProvisioner(project_prefix="aptl-dirtest")

        net_plan = ProvisioningPlan(
            resources={
                "provision.network.test-net": PlannedResource(
                    address="provision.network.test-net",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="network",
                    payload={"spec": {"properties": {"cidr": "172.31.0.0/24", "gateway": "172.31.0.1"}}},
                ),
            },
            operations=[
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.network.test-net",
                    resource_type="network",
                    payload={"spec": {"properties": {"cidr": "172.31.0.0/24", "gateway": "172.31.0.1"}}},
                ),
            ],
        )

        node_plan = ProvisioningPlan(
            resources={
                "provision.node.test-vm": PlannedResource(
                    address="provision.node.test-vm",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="node",
                    payload={
                        "node_name": "test-vm",
                        "spec": {"source": {"name": "ubuntu", "version": "22.04"}},
                        "ordering_dependencies": ["provision.network.test-net"],
                    },
                    ordering_dependencies=("provision.network.test-net",),
                ),
            },
            operations=[
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.node.test-vm",
                    resource_type="node",
                    payload={
                        "node_name": "test-vm",
                        "spec": {"source": {"name": "ubuntu", "version": "22.04"}},
                        "ordering_dependencies": ["provision.network.test-net"],
                    },
                    ordering_dependencies=("provision.network.test-net",),
                ),
            ],
        )

        dir_plan = ProvisioningPlan(
            resources={
                "provision.content.test-dir": PlannedResource(
                    address="provision.content.test-dir",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="content-placement",
                    payload={
                        "target_node": "test-vm",
                        "target_address": "provision.node.test-vm",
                        "spec": {"type": "directory", "destination": "/opt/test-data"},
                    },
                ),
            },
            operations=[
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.content.test-dir",
                    resource_type="content-placement",
                    payload={
                        "target_node": "test-vm",
                        "target_address": "provision.node.test-vm",
                        "spec": {"type": "directory", "destination": "/opt/test-data"},
                    },
                ),
            ],
        )

        try:
            snapshot = RuntimeSnapshot()
            # Create network, then node, then directory content
            result = provisioner.apply(net_plan, snapshot)
            assert result.success
            result = provisioner.apply(node_plan, result.snapshot)
            assert result.success
            result = provisioner.apply(dir_plan, result.snapshot)
            assert result.success

            # Verify directory exists in container
            cid = provisioner.containers.get("provision.node.test-vm")
            assert cid is not None
            check = subprocess.run(
                ["docker", "exec", cid, "test", "-d", "/opt/test-data"],
                capture_output=True,
            )
            assert check.returncode == 0, "Directory was not created in container"
        finally:
            provisioner.cleanup()

    def test_provisioner_cleanup(self):
        """Verify cleanup removes all Docker resources."""
        from aptl.core.runtime.models import (
            ProvisioningPlan,
            ProvisionOp,
            ChangeAction,
            PlannedResource,
        )

        provisioner = DockerProvisioner(project_prefix="aptl-cleanup-test")
        test_plan = ProvisioningPlan(
            resources={
                "provision.network.test-net": PlannedResource(
                    address="provision.network.test-net",
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type="network",
                    payload={"spec": {"properties": {"cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}}},
                ),
            },
            operations=[
                ProvisionOp(
                    action=ChangeAction.CREATE,
                    address="provision.network.test-net",
                    resource_type="network",
                    payload={"spec": {"properties": {"cidr": "172.30.0.0/24", "gateway": "172.30.0.1"}}},
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


@requires_docker
class TestScenarioExecution:
    """True end-to-end scenario execution with real SSH between containers.

    Provisions infrastructure using the panubo/sshd image, distributes SSH
    keys, executes the attack workflow (kali → server → workstation), and
    verifies flag capture, condition evaluation, and the scoring pipeline.
    """

    def test_ssh_lateral_movement_e2e(self):
        """Full attack scenario: SSH into server, lateral move to workstation."""
        import yaml

        scenario = parse_sdl_file(SCENARIO_PATH)
        model = compile_runtime_model(scenario)
        assert model.diagnostics == [], (
            f"Compile diagnostics: {[d.message for d in model.diagnostics]}"
        )

        # Load raw YAML for the orchestrator's scenario context
        with open(SCENARIO_PATH) as f:
            scenario_dict = yaml.safe_load(f)

        target = create_docker_target(
            project_prefix="aptl-e2e",
            scenario=scenario_dict,
        )
        execution_plan = plan(model, target.manifest)
        assert execution_plan.is_valid, (
            f"Plan diagnostics: {[d.message for d in execution_plan.diagnostics]}"
        )

        provisioner = target.provisioner
        assert isinstance(provisioner, DockerProvisioner)
        control_plane = RuntimeControlPlane(target)

        try:
            # --- Phase 1: Provision infrastructure ---
            prov_receipt = control_plane.submit_provisioning(
                execution_plan.provisioning,
            )
            assert prov_receipt.accepted, (
                f"Provisioning rejected: {prov_receipt.diagnostics}"
            )

            # Verify containers exist
            assert len(provisioner.containers) >= 3, (
                f"Expected >= 3 containers, got {len(provisioner.containers)}"
            )
            assert len(provisioner.networks) >= 2, (
                f"Expected >= 2 networks, got {len(provisioner.networks)}"
            )

            # Wait for SSH to be ready, then distribute keys
            provisioner.wait_for_ssh()
            provisioner.distribute_ssh_keys()

            # --- Phase 2: Verify infrastructure ---
            # Check that flags are placed correctly
            server_cid = provisioner.container_for_node("server")
            workstation_cid = provisioner.container_for_node("workstation")
            kali_cid = provisioner.container_for_node("kali")
            assert server_cid, "Server container not found"
            assert workstation_cid, "Workstation container not found"
            assert kali_cid, "Kali container not found"

            # Verify flag files exist
            server_flag = subprocess.run(
                ["docker", "exec", server_cid, "cat", "/home/admin/user.txt"],
                capture_output=True, text=True,
            )
            assert "FLAG{server-alpha-9f3c}" in server_flag.stdout, (
                f"Server flag not found: {server_flag.stdout!r}"
            )

            ws_flag = subprocess.run(
                ["docker", "exec", workstation_cid, "cat", "/home/admin/user.txt"],
                capture_output=True, text=True,
            )
            assert "FLAG{workstation-bravo-7e2d}" in ws_flag.stdout, (
                f"Workstation flag not found: {ws_flag.stdout!r}"
            )

            # Verify SSH is running on server and workstation
            for cid, name in [(server_cid, "server"), (workstation_cid, "workstation")]:
                ssh_check = subprocess.run(
                    ["docker", "exec", cid, "sh", "-c", "pgrep sshd"],
                    capture_output=True, text=True,
                )
                assert ssh_check.returncode == 0, f"sshd not running on {name}"

            # Verify admin accounts exist
            for cid, name in [(server_cid, "server"), (workstation_cid, "workstation")]:
                user_check = subprocess.run(
                    ["docker", "exec", cid, "id", "admin"],
                    capture_output=True, text=True,
                )
                assert user_check.returncode == 0, f"admin user not found on {name}"

            # --- Phase 3: Verify network topology ---
            # Kali can reach server (both on dmz-net)
            kali_to_server = subprocess.run(
                ["docker", "exec", kali_cid, "sh", "-c",
                 "nc -z -w3 server 22 && echo OK || echo FAIL"],
                capture_output=True, text=True,
            )
            assert "OK" in kali_to_server.stdout, (
                f"Kali cannot reach server: {kali_to_server.stdout!r}"
            )

            # Kali CANNOT directly reach workstation (different networks)
            kali_to_ws = subprocess.run(
                ["docker", "exec", kali_cid, "sh", "-c",
                 "nc -z -w2 workstation 22 && echo OK || echo FAIL"],
                capture_output=True, text=True, timeout=10,
            )
            assert "FAIL" in kali_to_ws.stdout, (
                f"Kali should NOT reach workstation directly: {kali_to_ws.stdout!r}"
            )

            # Server can reach workstation (both on internal-net)
            server_to_ws = subprocess.run(
                ["docker", "exec", server_cid, "sh", "-c",
                 "nc -z -w3 workstation 22 && echo OK || echo FAIL"],
                capture_output=True, text=True,
            )
            assert "OK" in server_to_ws.stdout, (
                f"Server cannot reach workstation: {server_to_ws.stdout!r}"
            )

            # --- Phase 4: Execute SSH attack (kali → server) ---
            ssh_server = subprocess.run(
                ["docker", "exec", kali_cid,
                 "ssh", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "LogLevel=ERROR",
                 "-i", "/root/.ssh/id_ed25519",
                 "admin@server", "cat", "/home/admin/user.txt"],
                capture_output=True, text=True, timeout=30,
            )
            assert ssh_server.returncode == 0, (
                f"SSH to server failed: {ssh_server.stderr!r}"
            )
            assert "FLAG{server-alpha-9f3c}" in ssh_server.stdout, (
                f"Server flag mismatch: {ssh_server.stdout!r}"
            )

            # --- Phase 5: Lateral movement (kali → server → workstation) ---
            ssh_lateral = subprocess.run(
                ["docker", "exec", kali_cid,
                 "ssh", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "LogLevel=ERROR",
                 "-i", "/root/.ssh/id_ed25519",
                 "admin@server",
                 "ssh -o StrictHostKeyChecking=no"
                 " -o UserKnownHostsFile=/dev/null"
                 " -o LogLevel=ERROR"
                 " -i /home/admin/.ssh/id_ed25519"
                 " admin@workstation cat /home/admin/user.txt"],
                capture_output=True, text=True, timeout=30,
            )
            assert ssh_lateral.returncode == 0, (
                f"Lateral movement SSH failed: {ssh_lateral.stderr!r}"
            )
            assert "FLAG{workstation-bravo-7e2d}" in ssh_lateral.stdout, (
                f"Workstation flag mismatch: {ssh_lateral.stdout!r}"
            )

            # --- Phase 6: Run orchestration (workflow execution) ---
            orch_receipt = control_plane.submit_orchestration(
                execution_plan.orchestration,
            )
            assert orch_receipt.accepted, (
                f"Orchestration rejected: {orch_receipt.diagnostics}"
            )

            # The orchestrator should have eagerly executed the attack workflow
            orchestrator = target.orchestrator
            assert isinstance(orchestrator, DockerOrchestrator)

            # Check captured flags from the orchestrator
            assert "capture-server-flag" in orchestrator.captured_flags, (
                f"Orchestrator didn't capture server flag: {orchestrator.captured_flags}"
            )
            assert "FLAG{server-alpha-9f3c}" in orchestrator.captured_flags["capture-server-flag"]

            assert "capture-workstation-flag" in orchestrator.captured_flags, (
                f"Orchestrator didn't capture workstation flag: {orchestrator.captured_flags}"
            )
            assert "FLAG{workstation-bravo-7e2d}" in orchestrator.captured_flags["capture-workstation-flag"]

            # Check workflow state
            snapshot = control_plane.snapshot
            atk_key = "orchestration.workflow.attack-workflow"
            assert atk_key in snapshot.orchestration_results
            atk_result = snapshot.orchestration_results[atk_key]
            assert atk_result["workflow_status"] == "succeeded", (
                f"Attack workflow status: {atk_result['workflow_status']}, "
                f"reason: {atk_result.get('terminal_reason')}"
            )

            # Check workflow history has step transitions
            atk_history = snapshot.orchestration_history.get(atk_key, [])
            step_events = [e for e in atk_history if e.get("event_type") == "step_completed"]
            assert len(step_events) >= 2, (
                f"Expected >= 2 step completions, got {len(step_events)}: {step_events}"
            )

            # --- Phase 7: Run evaluation ---
            eval_receipt = control_plane.submit_evaluation(
                execution_plan.evaluation,
            )
            assert eval_receipt.accepted, (
                f"Evaluation rejected: {eval_receipt.diagnostics}"
            )

            # Check evaluation results for conditions
            eval_results = control_plane.snapshot.evaluation_results
            assert len(eval_results) > 0, "No evaluation results"

            # Check scoring pipeline entries exist
            eval_entries = control_plane.snapshot.for_domain(RuntimeDomain.EVALUATION)
            metric_entries = {
                k for k in eval_entries if "metric" in k
            }
            assert len(metric_entries) >= 5, (
                f"Expected >= 5 metric entries, got {len(metric_entries)}"
            )

            eval_eval_entries = {
                k for k in eval_entries if "evaluation." in k and "metric" not in k
            }
            assert len(eval_eval_entries) >= 2, (
                f"Expected >= 2 evaluation entries, got {len(eval_eval_entries)}"
            )

        finally:
            provisioner.cleanup()
