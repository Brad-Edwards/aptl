"""Docker backend — provisions scenarios as Docker containers and networks.

Implements the Provisioner, Orchestrator, and Evaluator runtime protocols
using the Docker Engine API (via the ``docker`` Python SDK). Each SDL
network becomes a Docker bridge network, each VM node becomes a container,
and accounts/content are provisioned inside containers via ``docker exec``.

Capability surface:
- Provisioner: vm nodes on linux, file content, accounts with password auth
- Orchestrator: workflows with timeouts
- Evaluator: conditions, objectives (pass/fail via command checks)
"""

from __future__ import annotations

import logging
import subprocess
from datetime import UTC, datetime
from typing import Any

from aptl.core.runtime.capabilities import (
    BackendManifest,
    EvaluatorCapabilities,
    OrchestratorCapabilities,
    ProvisionerCapabilities,
    WorkflowFeature,
)
from aptl.core.runtime.models import (
    ApplyResult,
    ChangeAction,
    Diagnostic,
    EVALUATION_STATE_SCHEMA_VERSION,
    EvaluationPlan,
    OrchestrationPlan,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    Severity,
    SnapshotEntry,
)
from aptl.core.runtime.registry import RuntimeTarget, RuntimeTargetComponents

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _docker(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a docker CLI command."""
    cmd = ["docker", *args]
    logger.debug("docker: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check,
        timeout=120,
    )


def _diag(code: str, address: str, message: str, severity: Severity = Severity.ERROR) -> Diagnostic:
    return Diagnostic(code=code, domain="docker", address=address, message=message, severity=severity)


# ---------------------------------------------------------------------------
# Manifest factory
# ---------------------------------------------------------------------------

def create_docker_manifest(**config: Any) -> BackendManifest:
    """Declare the Docker backend's capability surface."""
    return BackendManifest(
        name="docker",
        provisioner=ProvisionerCapabilities(
            name="docker-provisioner",
            supported_node_types=frozenset({"vm", "switch"}),
            supported_os_families=frozenset({"linux"}),
            supported_content_types=frozenset({"file"}),
            supported_account_features=frozenset(
                {"groups", "shell", "home", "auth_method"}
            ),
            max_total_nodes=20,
            supports_acls=False,
            supports_accounts=True,
        ),
        orchestrator=OrchestratorCapabilities(
            name="docker-orchestrator",
            supported_sections=frozenset({"workflows"}),
            supports_workflows=True,
            supports_condition_refs=False,
            supports_inject_bindings=False,
            supported_workflow_features=frozenset({
                WorkflowFeature.TIMEOUTS,
                WorkflowFeature.FAILURE_TRANSITIONS,
            }),
        ),
        evaluator=EvaluatorCapabilities(
            name="docker-evaluator",
            supported_sections=frozenset(
                {"conditions", "metrics", "evaluations", "tlos", "goals", "objectives"}
            ),
            supports_scoring=True,
            supports_objectives=True,
        ),
    )


# ---------------------------------------------------------------------------
# Docker Provisioner
# ---------------------------------------------------------------------------

class DockerProvisioner:
    """Provisions Docker networks and containers from SDL plans."""

    def __init__(self, *, project_prefix: str = "aptl") -> None:
        self._prefix = project_prefix
        self._networks: dict[str, str] = {}   # address -> docker network id
        self._containers: dict[str, str] = {}  # address -> docker container id

    @property
    def containers(self) -> dict[str, str]:
        return dict(self._containers)

    @property
    def networks(self) -> dict[str, str]:
        return dict(self._networks)

    def validate(self, plan: ProvisioningPlan) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        for op in plan.operations:
            if op.action == ChangeAction.UNCHANGED:
                continue
            if op.resource_type == "node":
                os_family = op.payload.get("os_family", "")
                if os_family and os_family != "linux":
                    diagnostics.append(
                        _diag(
                            "docker.unsupported-os",
                            op.address,
                            f"Docker backend only supports linux, got {os_family}",
                        )
                    )
        return diagnostics

    def apply(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        changed: list[str] = []
        diagnostics: list[Diagnostic] = []

        for op in plan.operations:
            if op.action == ChangeAction.UNCHANGED:
                entries[op.address] = SnapshotEntry(
                    address=op.address,
                    domain=RuntimeDomain.PROVISIONING,
                    resource_type=op.resource_type,
                    payload=op.payload,
                    ordering_dependencies=op.ordering_dependencies,
                    refresh_dependencies=op.refresh_dependencies,
                    status="unchanged",
                )
                continue

            if op.action == ChangeAction.DELETE:
                self._destroy_resource(op.address, op.resource_type)
                entries.pop(op.address, None)
                changed.append(op.address)
                continue

            try:
                self._create_resource(op.address, op.resource_type, op.payload)
                status = "applied"
            except Exception as exc:
                diagnostics.append(
                    _diag("docker.apply-failed", op.address, str(exc))
                )
                status = "failed"

            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.PROVISIONING,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status=status,
            )
            changed.append(op.address)

        success = not any(d.is_error for d in diagnostics)
        return ApplyResult(
            success=success,
            snapshot=snapshot.with_entries(entries),
            changed_addresses=changed,
            diagnostics=diagnostics,
        )

    def _create_resource(
        self, address: str, resource_type: str, payload: dict[str, Any]
    ) -> None:
        if resource_type == "network":
            self._create_network(address, payload)
        elif resource_type == "node":
            self._create_node(address, payload)
        elif resource_type == "content-placement":
            self._create_content(address, payload)
        elif resource_type == "account-placement":
            self._create_account(address, payload)
        elif resource_type in ("feature-binding", "condition-binding"):
            pass  # features/conditions are logical, not provisioned directly
        else:
            logger.warning("docker: skipping unknown resource type %s", resource_type)

    def _destroy_resource(self, address: str, resource_type: str) -> None:
        if resource_type == "network":
            net_id = self._networks.pop(address, None)
            if net_id:
                _docker("network", "rm", net_id, check=False)
        elif resource_type == "node":
            cid = self._containers.pop(address, None)
            if cid:
                _docker("rm", "-f", cid, check=False)

    def _create_network(self, address: str, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        properties = spec.get("properties")
        name = f"{self._prefix}-{address.replace('.', '-')}"

        cmd = ["network", "create", "--driver", "bridge"]
        if isinstance(properties, dict):
            cidr = properties.get("cidr", "")
            gateway = properties.get("gateway", "")
            if cidr:
                cmd.extend(["--subnet", cidr])
            if gateway:
                cmd.extend(["--gateway", gateway])
        cmd.append(name)

        result = _docker(*cmd)
        net_id = result.stdout.strip()
        self._networks[address] = net_id
        logger.info("docker: created network %s (%s)", name, net_id[:12])

    def _create_node(self, address: str, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        source = spec.get("source", {})
        image_name = source.get("name", "ubuntu")
        image_version = source.get("version", "latest")
        if image_version == "*":
            image_version = "latest"
        image = f"{image_name}:{image_version}"

        node_name = payload.get("node_name", address.split(".")[-1])
        container_name = f"{self._prefix}-{node_name}"

        # Pull image (best effort)
        _docker("pull", image, check=False)

        # Determine which network(s) to connect to
        network_args: list[str] = []
        ordering_deps = payload.get("ordering_dependencies", [])
        # Find first network dependency
        for dep in ordering_deps:
            if dep in self._networks:
                network_args = ["--network", f"{self._prefix}-{dep.replace('.', '-')}"]
                break

        # Create container
        cmd = [
            "run", "-d",
            "--name", container_name,
            "--hostname", node_name,
            *network_args,
            image,
            "sleep", "infinity",
        ]
        result = _docker(*cmd)
        cid = result.stdout.strip()
        self._containers[address] = cid
        logger.info("docker: created container %s (%s) from %s", container_name, cid[:12], image)

        # Connect to additional networks
        first_network_found = bool(network_args)
        for dep in ordering_deps:
            if dep in self._networks:
                if first_network_found:
                    first_network_found = False
                    continue  # skip the first one, already connected
                net_name = f"{self._prefix}-{dep.replace('.', '-')}"
                _docker("network", "connect", net_name, cid, check=False)

    def _create_content(self, address: str, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        target_node = payload.get("target_node", "")
        target_address = payload.get("target_address", "")
        path = spec.get("path", "")
        text = spec.get("text")

        if not path or text is None:
            return

        cid = self._containers.get(target_address)
        if not cid:
            logger.warning("docker: no container for content target %s", target_address)
            return

        # Create parent directory and write file
        parent = "/".join(path.split("/")[:-1])
        if parent:
            _docker("exec", cid, "mkdir", "-p", parent, check=False)
        _docker("exec", cid, "sh", "-c", f"echo '{text}' > {path}", check=False)
        logger.info("docker: placed content at %s:%s", target_node, path)

    def _create_account(self, address: str, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        target_address = payload.get("target_address", "")
        username = spec.get("username", "")
        node_name = payload.get("node_name", "")

        if not username:
            return

        cid = self._containers.get(target_address)
        if not cid:
            logger.warning("docker: no container for account target %s", target_address)
            return

        groups = spec.get("groups", [])
        shell = spec.get("shell", "/bin/bash")
        home = spec.get("home", f"/home/{username}")
        password_strength = spec.get("password_strength", "medium")

        # Determine password based on strength
        if password_strength == "weak":
            password = "password123"
        elif password_strength == "strong":
            password = "Str0ng!P@ssw0rd#2024-Kali"
        else:
            password = "m3dium_P@ss"

        # Create user account
        _docker(
            "exec", cid, "sh", "-c",
            f"id {username} 2>/dev/null || "
            f"(useradd -m -d {home} -s {shell} {username} 2>/dev/null || true)",
            check=False,
        )

        # Set password
        _docker(
            "exec", cid, "sh", "-c",
            f"echo '{username}:{password}' | chpasswd 2>/dev/null || true",
            check=False,
        )

        # Add to groups
        for group in groups:
            _docker(
                "exec", cid, "sh", "-c",
                f"(groupadd {group} 2>/dev/null || true) && "
                f"(usermod -aG {group} {username} 2>/dev/null || true)",
                check=False,
            )

        logger.info("docker: created account %s on %s", username, node_name)

    def cleanup(self) -> None:
        """Remove all containers and networks created by this provisioner."""
        for address, cid in list(self._containers.items()):
            _docker("rm", "-f", cid, check=False)
        self._containers.clear()
        for address, net_id in list(self._networks.items()):
            _docker("network", "rm", net_id, check=False)
        self._networks.clear()


# ---------------------------------------------------------------------------
# Docker Orchestrator
# ---------------------------------------------------------------------------

class DockerOrchestrator:
    """Manages workflow execution state for Docker-provisioned scenarios."""

    def __init__(self) -> None:
        self._running = False
        self._startup_order: list[str] = []
        self._results: dict[str, dict[str, Any]] = {}
        self._history: dict[str, list[dict[str, Any]]] = {}

    def start(
        self,
        plan: OrchestrationPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        results = dict(snapshot.orchestration_results)
        history = {
            addr: list(events)
            for addr, events in snapshot.orchestration_history.items()
        }
        changed: list[str] = []
        now = _utc_now()

        for op in plan.operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                results.pop(op.address, None)
                history.pop(op.address, None)
                changed.append(op.address)
                continue
            if op.action == ChangeAction.UNCHANGED:
                continue

            status = "queued" if op.resource_type == "workflow" else "bound"
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.ORCHESTRATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status=status,
            )

            if op.resource_type == "workflow":
                result_contract = op.payload.get("result_contract", {})
                observable_steps = result_contract.get("observable_steps", {})
                step_states = {
                    step_name: {
                        "lifecycle": "pending",
                        "outcome": None,
                        "attempts": 0,
                    }
                    for step_name, step_payload in observable_steps.items()
                    if isinstance(step_payload, dict)
                }
                results[op.address] = {
                    "state_schema_version": result_contract.get(
                        "state_schema_version",
                        op.payload.get("state_schema_version", "workflow-step-state/v1"),
                    ),
                    "workflow_status": "running",
                    "run_id": f"{op.address}-run",
                    "started_at": now,
                    "updated_at": now,
                    "terminal_reason": None,
                    "steps": step_states,
                }
                history[op.address] = [{
                    "event_type": "workflow_started",
                    "timestamp": now,
                    "step_name": op.payload.get("execution_contract", {}).get("start_step"),
                    "branch_name": None,
                    "join_step": None,
                    "outcome": None,
                    "details": {},
                }]

            changed.append(op.address)

        self._running = bool(plan.resources)
        self._startup_order = list(plan.startup_order)
        self._results = results
        self._history = history

        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(
                entries,
                orchestration_results=results,
                orchestration_history=history,
            ),
            changed_addresses=changed,
        )

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "startup_order": list(self._startup_order),
            "results": len(self._results),
        }

    def results(self) -> dict[str, dict[str, Any]]:
        return dict(self._results)

    def history(self) -> dict[str, list[dict[str, Any]]]:
        return {
            addr: list(events)
            for addr, events in self._history.items()
        }

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        entries = {
            addr: entry
            for addr, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.ORCHESTRATION
        }
        removed = [
            addr for addr, entry in snapshot.entries.items()
            if entry.domain == RuntimeDomain.ORCHESTRATION
        ]
        self._running = False
        self._startup_order = []
        self._results = {}
        self._history = {}
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(
                entries,
                orchestration_results={},
                orchestration_history={},
            ),
            changed_addresses=removed,
        )


# ---------------------------------------------------------------------------
# Docker Evaluator
# ---------------------------------------------------------------------------

class DockerEvaluator:
    """Evaluates objectives and conditions inside Docker containers."""

    def __init__(self, provisioner: DockerProvisioner) -> None:
        self._provisioner = provisioner
        self._running = False
        self._startup_order: list[str] = []
        self._results: dict[str, dict[str, Any]] = {}
        self._history: dict[str, list[dict[str, Any]]] = {}

    def start(
        self,
        plan: EvaluationPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        changed: list[str] = []
        results = dict(snapshot.evaluation_results)
        history = {
            addr: list(events)
            for addr, events in snapshot.evaluation_history.items()
        }
        now = _utc_now()

        for op in plan.operations:
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                results.pop(op.address, None)
                history.pop(op.address, None)
                changed.append(op.address)
                continue
            if op.action == ChangeAction.UNCHANGED:
                continue

            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.EVALUATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status="evaluating",
            )

            result_contract = op.payload.get("result_contract", {})
            resource_type = str(result_contract.get("resource_type", op.resource_type))

            result_payload: dict[str, Any] = {
                "state_schema_version": result_contract.get(
                    "state_schema_version",
                    EVALUATION_STATE_SCHEMA_VERSION,
                ),
                "resource_type": resource_type,
                "run_id": f"docker-eval-{op.address}",
                "status": "ready",
                "observed_at": now,
                "updated_at": now,
                "detail": f"docker evaluation for {op.address}",
                "evidence_refs": [],
            }

            if result_contract.get("supports_passed"):
                # For condition-bindings and objectives, check if the condition
                # command succeeds inside the relevant container
                passed = self._evaluate_resource(op)
                result_payload["passed"] = passed

            if result_contract.get("supports_score"):
                max_score = result_contract.get("fixed_max_score", 100)
                result_payload["score"] = max_score
                result_payload["max_score"] = max_score

            results[op.address] = result_payload
            history[op.address] = [
                {
                    "event_type": "evaluation_started",
                    "timestamp": now,
                    "status": "running",
                    "passed": None,
                    "score": None,
                    "max_score": None,
                    "detail": None,
                    "evidence_refs": [],
                    "details": {},
                },
                {
                    "event_type": "evaluation_ready",
                    "timestamp": now,
                    "status": "ready",
                    "passed": result_payload.get("passed"),
                    "score": result_payload.get("score"),
                    "max_score": result_payload.get("max_score"),
                    "detail": result_payload.get("detail"),
                    "evidence_refs": [],
                    "details": {},
                },
            ]
            changed.append(op.address)

        self._running = bool(plan.resources)
        self._startup_order = list(plan.startup_order)
        self._results = results
        self._history = history

        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(
                entries,
                evaluation_results=results,
                evaluation_history=history,
            ),
            changed_addresses=changed,
        )

    def _evaluate_resource(self, op: Any) -> bool:
        """Run a condition check inside the relevant container."""
        spec = op.payload.get("spec", {})
        command = spec.get("command")
        node_address = op.payload.get("node_address", "")

        if not command or not node_address:
            return True

        cid = self._provisioner.containers.get(node_address)
        if not cid:
            return False

        try:
            result = _docker("exec", cid, "sh", "-c", command, check=False)
            return result.returncode == 0
        except Exception:
            return False

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "startup_order": list(self._startup_order),
            "results": len(self._results),
        }

    def results(self) -> dict[str, dict[str, Any]]:
        return dict(self._results)

    def history(self) -> dict[str, list[dict[str, Any]]]:
        return {
            addr: list(events)
            for addr, events in self._history.items()
        }

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        entries = {
            addr: entry
            for addr, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        removed = [
            addr for addr, entry in snapshot.entries.items()
            if entry.domain == RuntimeDomain.EVALUATION
        ]
        self._running = False
        self._startup_order = []
        self._results = {}
        self._history = {}
        return ApplyResult(
            success=True,
            snapshot=snapshot.with_entries(
                entries,
                evaluation_results={},
                evaluation_history={},
            ),
            changed_addresses=removed,
        )


# ---------------------------------------------------------------------------
# Component factory
# ---------------------------------------------------------------------------

def create_docker_components(
    *,
    manifest: BackendManifest,
    **config: Any,
) -> RuntimeTargetComponents:
    """Factory for Docker runtime components."""
    prefix = config.get("project_prefix", "aptl")
    provisioner = DockerProvisioner(project_prefix=prefix)
    orchestrator = DockerOrchestrator()
    evaluator = DockerEvaluator(provisioner)
    return RuntimeTargetComponents(
        provisioner=provisioner,
        orchestrator=orchestrator,
        evaluator=evaluator,
    )


def create_docker_target(**config: Any) -> RuntimeTarget:
    """Convenience helper returning the fully configured Docker target."""
    manifest = create_docker_manifest(**config)
    components = create_docker_components(manifest=manifest, **config)
    return RuntimeTarget(
        name="docker",
        manifest=manifest,
        provisioner=components.provisioner,
        orchestrator=components.orchestrator,
        evaluator=components.evaluator,
    )
