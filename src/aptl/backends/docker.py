"""Docker reference backend for the first honest runtime-backed scenario.

This backend is intentionally narrow. It exists to prove that one portable
scenario can be fully driven through the runtime surfaces on Docker without
hidden YAML side channels, undeclared trust relationships, or evaluator
shortcuts.

Supported subset:
- provisioning of linux VM-like containers and bridge networks
- account creation
- file and directory content placement
- one concrete service feature binding: ``http-service``
- condition evaluation
- conditional metric scoring
- evaluation/TLO/goal/objective pass/fail derivation
- workflow execution over evaluated objective/condition state
- inject/event/script/story resources as orchestration state
"""

from __future__ import annotations

import logging
import shlex
import subprocess
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

import yaml

try:
    import docker as docker_sdk
except ImportError:  # pragma: no cover - optional dependency
    docker_sdk = None  # type: ignore[assignment]

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
    EvaluationExecutionState,
    EvaluationHistoryEvent,
    EvaluationHistoryEventType,
    EvaluationOp,
    EvaluationPlan,
    EvaluationResultContract,
    EvaluationResultStatus,
    OrchestrationPlan,
    ProvisioningPlan,
    RuntimeDomain,
    RuntimeSnapshot,
    Severity,
    SnapshotEntry,
    WorkflowExecutionState,
    WorkflowHistoryEvent,
    WorkflowHistoryEventType,
    WorkflowStepExecutionState,
    WorkflowStepLifecycle,
    WorkflowStepOutcome,
    WorkflowStatus,
)
from aptl.core.runtime.registry import RuntimeTarget, RuntimeTargetComponents

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExecResult:
    """Result of a command executed in a container."""

    exit_code: int
    output: str


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _diag(
    code: str,
    address: str,
    message: str,
    severity: Severity = Severity.ERROR,
) -> Diagnostic:
    return Diagnostic(code=code, domain="docker", address=address, message=message, severity=severity)


def _get_docker_client() -> Any:
    if docker_sdk is None:
        raise RuntimeError(
            "The 'docker' Python package is required for the Docker backend. "
            "Install it with: pip install 'docker>=7.0.0'"
        )
    return docker_sdk.DockerClient.from_env()


def _exec_run(
    client: Any,
    container_id: str,
    cmd: list[str] | str,
) -> ExecResult:
    container = client.containers.get(container_id)
    if isinstance(cmd, str):
        cmd = ["sh", "-c", cmd]
    exit_code, output = container.exec_run(cmd, demux=False)
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else (output or "")
    return ExecResult(exit_code=exit_code, output=text)


T = TypeVar("T")


def _ordered_operations(
    operations: Iterable[T],
    startup_order: Iterable[str],
) -> list[T]:
    op_list = list(operations)
    order_index = {address: index for index, address in enumerate(startup_order)}
    return sorted(
        op_list,
        key=lambda op: (order_index.get(getattr(op, "address", ""), len(order_index)), getattr(op, "address", "")),
    )


def _result_payload(
    state: EvaluationExecutionState,
) -> dict[str, Any]:
    return state.to_payload()


def _history_payloads(
    events: Iterable[EvaluationHistoryEvent],
) -> list[dict[str, Any]]:
    return [event.to_payload() for event in events]


def _workflow_history_payloads(
    events: Iterable[WorkflowHistoryEvent],
) -> list[dict[str, Any]]:
    return [event.to_payload() for event in events]


def _coerce_iso_now() -> str:
    return _utc_now()


def create_docker_manifest(**config: Any) -> BackendManifest:
    """Declare the Docker backend's honest reference capability surface."""

    return BackendManifest(
        name="docker",
        provisioner=ProvisionerCapabilities(
            name="docker-provisioner",
            supported_node_types=frozenset({"vm", "switch"}),
            supported_os_families=frozenset({"linux"}),
            supported_content_types=frozenset({"file", "directory"}),
            supported_account_features=frozenset({"groups", "shell", "home"}),
            max_total_nodes=12,
            supports_acls=False,
            supports_accounts=True,
            constraints={
                "feature_bindings": "http-service only",
                "node_runtime": "linux containers only",
            },
        ),
        orchestrator=OrchestratorCapabilities(
            name="docker-orchestrator",
            supported_sections=frozenset(
                {"injects", "events", "scripts", "stories", "workflows"}
            ),
            supports_workflows=True,
            supports_condition_refs=True,
            supports_inject_bindings=False,
            supported_workflow_features=frozenset(
                {
                    WorkflowFeature.TIMEOUTS,
                    WorkflowFeature.FAILURE_TRANSITIONS,
                    WorkflowFeature.DECISION,
                }
            ),
            constraints={
                "workflow_execution": "objective steps observe evaluated objective state; decision steps observe evaluated condition/objective state",
                "unsupported_steps": "retry,switch,call,parallel,join,compensation",
            },
        ),
        evaluator=EvaluatorCapabilities(
            name="docker-evaluator",
            supported_sections=frozenset(
                {"conditions", "metrics", "evaluations", "tlos", "goals", "objectives"}
            ),
            supports_scoring=True,
            supports_objectives=True,
            constraints={
                "metric_types": "conditional metrics only",
            },
        ),
    )


class DockerProvisioner:
    """Provision Docker networks and linux containers from runtime plans."""

    def __init__(
        self,
        *,
        project_prefix: str = "aptl",
    ) -> None:
        self._prefix = project_prefix
        self._networks: dict[str, str] = {}
        self._containers: dict[str, str] = {}
        self._node_names: dict[str, str] = {}
        self._accounts: dict[str, dict[str, Any]] = {}
        self._compose_dir: Path | None = None
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = _get_docker_client()
        return self._client

    @property
    def containers(self) -> dict[str, str]:
        return dict(self._containers)

    @property
    def networks(self) -> dict[str, str]:
        return dict(self._networks)

    @property
    def node_names(self) -> dict[str, str]:
        return dict(self._node_names)

    def container_for_node(self, node_name: str) -> str | None:
        for address, mapped_name in self._node_names.items():
            if mapped_name == node_name:
                return self._containers.get(address)
        return None

    def validate(self, plan: ProvisioningPlan) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        for op in plan.operations:
            if op.action == ChangeAction.UNCHANGED:
                continue
            if op.resource_type == "node":
                os_family = str(op.payload.get("os_family", "")).lower()
                if os_family and os_family != "linux":
                    diagnostics.append(
                        _diag(
                            "docker.unsupported-os",
                            op.address,
                            f"Docker backend only supports linux nodes, got {os_family!r}.",
                        )
                    )
            if op.resource_type == "feature-binding":
                feature_name = str(op.payload.get("feature_name", ""))
                if feature_name and feature_name != "http-service":
                    diagnostics.append(
                        _diag(
                            "docker.unsupported-feature-binding",
                            op.address,
                            f"Docker reference backend only supports the 'http-service' feature, got {feature_name!r}.",
                        )
                    )
            if op.resource_type == "account-placement":
                auth_method = op.payload.get("spec", {}).get("auth_method")
                if auth_method not in (None, "", "password"):
                    diagnostics.append(
                        _diag(
                            "docker.unsupported-account-auth-method",
                            op.address,
                            "Docker reference backend only supports password-authenticated accounts.",
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

        compose_ops: list[Any] = []
        post_ops: list[Any] = []

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

            if op.resource_type in {"network", "node"}:
                compose_ops.append(op)
            else:
                post_ops.append(op)

        if compose_ops:
            try:
                self._compose_up(compose_ops)
                for op in compose_ops:
                    entries[op.address] = SnapshotEntry(
                        address=op.address,
                        domain=RuntimeDomain.PROVISIONING,
                        resource_type=op.resource_type,
                        payload=op.payload,
                        ordering_dependencies=op.ordering_dependencies,
                        refresh_dependencies=op.refresh_dependencies,
                        status="applied",
                    )
                    changed.append(op.address)
            except Exception as exc:
                message = f"Docker Compose failed before post-provision operations could run: {exc}"
                for op in compose_ops:
                    diagnostics.append(_diag("docker.compose-failed", op.address, message))
                    entries[op.address] = SnapshotEntry(
                        address=op.address,
                        domain=RuntimeDomain.PROVISIONING,
                        resource_type=op.resource_type,
                        payload=op.payload,
                        ordering_dependencies=op.ordering_dependencies,
                        refresh_dependencies=op.refresh_dependencies,
                        status="failed",
                    )
                    changed.append(op.address)
                return ApplyResult(
                    success=False,
                    snapshot=snapshot.with_entries(entries),
                    changed_addresses=changed,
                    diagnostics=diagnostics,
                )

        for op in post_ops:
            try:
                self._create_resource(
                    op.address,
                    op.resource_type,
                    op.payload,
                )
                status = "applied"
            except Exception as exc:
                diagnostics.append(_diag("docker.apply-failed", op.address, str(exc)))
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

        return ApplyResult(
            success=not any(diag.is_error for diag in diagnostics),
            snapshot=snapshot.with_entries(entries),
            changed_addresses=changed,
            diagnostics=diagnostics,
        )

    def _compose_up(self, ops: list[Any]) -> None:
        network_ops = [op for op in ops if op.resource_type == "network"]
        node_ops = [op for op in ops if op.resource_type == "node"]

        if network_ops and not node_ops:
            self._create_networks_directly(network_ops)
            return

        compose: dict[str, Any] = {"services": {}, "networks": {}}

        for op in network_ops:
            spec = op.payload.get("spec", {})
            properties = spec.get("properties")
            net_name = op.address.replace(".", "-")
            network_def: dict[str, Any] = {"driver": "bridge"}
            if isinstance(properties, dict):
                cidr = properties.get("cidr", "")
                gateway = properties.get("gateway", "")
                if cidr:
                    ipam_config: dict[str, str] = {"subnet": cidr}
                    if gateway:
                        ipam_config["gateway"] = gateway
                    network_def["ipam"] = {"config": [ipam_config]}
            compose["networks"][net_name] = network_def

        for op in node_ops:
            spec = op.payload.get("spec", {})
            source = spec.get("source", {})
            image_name = source.get("name", "ubuntu")
            image_version = source.get("version", "latest")
            if image_version == "*":
                image_version = "latest"
            image = f"{image_name}:{image_version}"

            node_name = op.payload.get("node_name", op.address.split(".")[-1])
            container_name = f"{self._prefix}-{node_name}"

            service: dict[str, Any] = {
                "image": image,
                "container_name": container_name,
                "hostname": node_name,
                "command": "sleep infinity",
            }

            network_deps: list[str] = []
            for dependency in op.ordering_dependencies:
                dep_key = dependency.replace(".", "-")
                if dep_key in compose["networks"]:
                    network_deps.append(dep_key)
                elif dependency in self._networks:
                    compose["networks"][dep_key] = {
                        "external": True,
                        "name": f"{self._prefix}-{dep_key}",
                    }
                    network_deps.append(dep_key)

            if network_deps:
                service["networks"] = {
                    net_key: {"aliases": [node_name]} for net_key in network_deps
                }

            compose["services"][node_name] = service
            self._node_names[op.address] = node_name

        if not compose["networks"]:
            del compose["networks"]
        if not compose["services"]:
            del compose["services"]

        self._compose_dir = Path(tempfile.mkdtemp(prefix=f"{self._prefix}-compose-"))
        compose_path = self._compose_dir / "docker-compose.yml"
        compose_path.write_text(
            yaml.dump(compose, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )

        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(compose_path),
                "-p",
                self._prefix,
                "up",
                "-d",
                "--wait",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )

        client = self._get_client()
        for op in network_ops:
            net_name = f"{self._prefix}_{op.address.replace('.', '-')}"
            try:
                net = client.networks.get(net_name)
                self._networks[op.address] = net.id
            except Exception:
                self._networks[op.address] = net_name

        for op in node_ops:
            node_name = op.payload.get("node_name", op.address.split(".")[-1])
            container_name = f"{self._prefix}-{node_name}"
            container = client.containers.get(container_name)
            self._containers[op.address] = container.id

    def _create_networks_directly(self, network_ops: list[Any]) -> None:
        client = self._get_client()
        for op in network_ops:
            spec = op.payload.get("spec", {})
            properties = spec.get("properties")
            name = f"{self._prefix}-{op.address.replace('.', '-')}"
            ipam_pool_configs = []
            if isinstance(properties, dict):
                cidr = properties.get("cidr", "")
                gateway = properties.get("gateway", "")
                if cidr:
                    pool = docker_sdk.types.IPAMPool(subnet=cidr, gateway=gateway or None)
                    ipam_pool_configs.append(pool)
            ipam_config = (
                docker_sdk.types.IPAMConfig(pool_configs=ipam_pool_configs)
                if ipam_pool_configs
                else None
            )
            network = client.networks.create(name, driver="bridge", ipam=ipam_config)
            self._networks[op.address] = network.id

    def _create_resource(
        self,
        address: str,
        resource_type: str,
        payload: dict[str, Any],
    ) -> None:
        if resource_type == "content-placement":
            self._create_content(payload)
            return
        if resource_type == "account-placement":
            self._create_account(address, payload)
            return
        if resource_type == "feature-binding":
            self._create_feature_binding(address, payload)
            return
        if resource_type == "condition-binding":
            return
        raise ValueError(f"Unsupported provisioning resource type {resource_type!r}.")

    def _destroy_resource(self, address: str, resource_type: str) -> None:
        if resource_type == "network":
            net_id = self._networks.pop(address, None)
            if net_id:
                try:
                    self._get_client().networks.get(net_id).remove()
                except Exception:
                    pass
        elif resource_type == "node":
            container_id = self._containers.pop(address, None)
            if container_id:
                try:
                    self._get_client().containers.get(container_id).remove(force=True)
                except Exception:
                    pass

    def _create_content(self, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        target_address = payload.get("target_address", "")
        content_type = spec.get("type", "file")
        container_id = self._containers.get(target_address)
        if not container_id:
            raise ValueError(f"No container exists for content target {target_address!r}.")

        client = self._get_client()
        if content_type == "directory":
            destination = spec.get("destination", "")
            if not destination:
                raise ValueError("Directory content placement requires a destination.")
            result = _exec_run(client, container_id, ["mkdir", "-p", destination])
            if result.exit_code != 0:
                raise ValueError(f"Failed to create directory {destination!r}: {result.output.strip()}")
            return

        if content_type != "file":
            raise ValueError(f"Unsupported content type {content_type!r}.")

        path = spec.get("path", "")
        text = spec.get("text")
        if not path or text is None:
            raise ValueError("File content placement requires both path and text.")

        parent = str(Path(path).parent)
        if parent and parent != ".":
            mkdir = _exec_run(client, container_id, ["mkdir", "-p", parent])
            if mkdir.exit_code != 0:
                raise ValueError(f"Failed to create parent directory {parent!r}: {mkdir.output.strip()}")
        write = _exec_run(
            client,
            container_id,
            ["sh", "-c", f"printf '%s\\n' {shlex.quote(str(text))} > {shlex.quote(path)}"],
        )
        if write.exit_code != 0:
            raise ValueError(f"Failed to place content at {path!r}: {write.output.strip()}")

    def _create_account(self, address: str, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        target_address = payload.get("target_address", "")
        container_id = self._containers.get(target_address)
        if not container_id:
            raise ValueError(f"No container exists for account target {target_address!r}.")

        username = spec.get("username", "")
        if not username:
            raise ValueError("Account placement requires a username.")
        auth_method = spec.get("auth_method", "password")
        if auth_method not in ("", None, "password"):
            raise ValueError(
                f"Docker reference backend only supports password accounts; got {auth_method!r}."
            )

        groups = spec.get("groups", [])
        shell = spec.get("shell", "/bin/bash")
        home = spec.get("home", f"/home/{username}")
        password_strength = spec.get("password_strength", "medium")
        if password_strength == "weak":
            password = "password123"
        elif password_strength == "strong":
            password = "Str0ng!P@ssw0rd#2024"
        else:
            password = "m3dium_P@ss"

        client = self._get_client()
        create_user = _exec_run(
            client,
            container_id,
            (
                f"id {shlex.quote(username)} >/dev/null 2>&1 || "
                f"(getent group {shlex.quote(username)} >/dev/null 2>&1 "
                f"|| groupadd {shlex.quote(username)}) && "
                f"useradd -m -d {shlex.quote(home)} -s {shlex.quote(shell)} "
                f"-g {shlex.quote(username)} {shlex.quote(username)}"
            ),
        )
        if create_user.exit_code != 0:
            raise ValueError(f"Failed to create account {username!r}: {create_user.output.strip()}")

        set_password = _exec_run(
            client,
            container_id,
            f"echo {shlex.quote(username + ':' + password)} | chpasswd",
        )
        if set_password.exit_code != 0:
            raise ValueError(f"Failed to set password for {username!r}: {set_password.output.strip()}")

        for group in groups:
            add_group = _exec_run(
                client,
                container_id,
                (
                    f"(getent group {shlex.quote(group)} >/dev/null 2>&1 || groupadd {shlex.quote(group)}) "
                    f"&& usermod -aG {shlex.quote(group)} {shlex.quote(username)}"
                ),
            )
            if add_group.exit_code != 0:
                raise ValueError(
                    f"Failed to assign group {group!r} to {username!r}: {add_group.output.strip()}"
                )

        self._accounts[address] = {**spec, "node_name": payload.get("node_name", "")}

    def _create_feature_binding(self, address: str, payload: dict[str, Any]) -> None:
        feature_name = payload.get("feature_name", "")
        node_address = payload.get("node_address", "")
        container_id = self._containers.get(node_address)
        if not container_id:
            raise ValueError(f"No container exists for feature target {node_address!r}.")
        if feature_name != "http-service":
            raise ValueError(
                f"Docker reference backend only supports the 'http-service' feature, got {feature_name!r}."
            )
        self._install_http_service(container_id)

    def _install_http_service(self, container_id: str) -> None:
        client = self._get_client()
        ensure_python = _exec_run(
            client,
            container_id,
            (
                "command -v python3 >/dev/null 2>&1 || "
                "(apt-get update -qq >/dev/null 2>&1 && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null 2>&1)"
            ),
        )
        if ensure_python.exit_code != 0:
            raise ValueError(f"Failed to ensure python3 is installed: {ensure_python.output.strip()}")

        prepare = _exec_run(
            client,
            container_id,
            ["mkdir", "-p", "/srv/reference-site", "/var/log"],
        )
        if prepare.exit_code != 0:
            raise ValueError(f"Failed to prepare reference site directories: {prepare.output.strip()}")

        start = _exec_run(
            client,
            container_id,
            (
                "python3 -c \"import socket, sys; "
                "sock = socket.socket(); sock.settimeout(1); "
                "rc = sock.connect_ex(('127.0.0.1', 80)); sock.close(); "
                "sys.exit(0 if rc == 0 else 1)\" >/dev/null 2>&1 "
                "|| (python3 -m http.server 80 --bind 0.0.0.0 "
                "--directory /srv/reference-site >/var/log/reference-http.log 2>&1 &)"
            ),
        )
        if start.exit_code != 0:
            raise ValueError(f"Failed to start reference HTTP service: {start.output.strip()}")

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            health = _exec_run(
                client,
                container_id,
                (
                    "python3 -c \"import socket; "
                    "s = socket.create_connection(('127.0.0.1', 80), 1); s.close()\""
                ),
            )
            if health.exit_code == 0:
                return
            time.sleep(0.5)
        raise ValueError("Reference HTTP service did not become reachable on port 80.")

    def cleanup(self) -> None:
        if self._compose_dir and (self._compose_dir / "docker-compose.yml").exists():
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(self._compose_dir / "docker-compose.yml"),
                    "-p",
                    self._prefix,
                    "down",
                    "-v",
                    "--remove-orphans",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

        if self._client is not None:
            for container_id in list(self._containers.values()):
                try:
                    self._client.containers.get(container_id).remove(force=True)
                except Exception:
                    pass
            for network_id in list(self._networks.values()):
                try:
                    self._client.networks.get(network_id).remove()
                except Exception:
                    pass

        self._containers.clear()
        self._networks.clear()
        self._node_names.clear()
        self._accounts.clear()
        self._compose_dir = None
        self._client = None


class DockerOrchestrator:
    """Execute workflows strictly from compiled payloads and evaluation state."""

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
            address: list(events)
            for address, events in snapshot.orchestration_history.items()
        }
        changed: list[str] = []
        diagnostics: list[Diagnostic] = []

        for op in _ordered_operations(plan.operations, plan.startup_order):
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                results.pop(op.address, None)
                history.pop(op.address, None)
                changed.append(op.address)
                continue
            if op.action == ChangeAction.UNCHANGED:
                continue

            if op.resource_type != "workflow":
                entries[op.address] = SnapshotEntry(
                    address=op.address,
                    domain=RuntimeDomain.ORCHESTRATION,
                    resource_type=op.resource_type,
                    payload=op.payload,
                    ordering_dependencies=op.ordering_dependencies,
                    refresh_dependencies=op.refresh_dependencies,
                    status="bound",
                )
                changed.append(op.address)
                continue

            workflow_result, workflow_history, workflow_diagnostics = self._execute_workflow(
                workflow_address=op.address,
                payload=op.payload,
                snapshot=snapshot,
            )
            diagnostics.extend(workflow_diagnostics)
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.ORCHESTRATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status=workflow_result.workflow_status.value,
            )
            results[op.address] = workflow_result.to_payload()
            history[op.address] = _workflow_history_payloads(workflow_history)
            changed.append(op.address)

        self._running = bool(plan.resources)
        self._startup_order = list(plan.startup_order)
        self._results = results
        self._history = history

        return ApplyResult(
            success=not any(diag.is_error for diag in diagnostics),
            snapshot=snapshot.with_entries(
                entries,
                orchestration_results=results,
                orchestration_history=history,
            ),
            changed_addresses=changed,
            diagnostics=diagnostics,
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
            address: list(events)
            for address, events in self._history.items()
        }

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        entries = {
            address: entry
            for address, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.ORCHESTRATION
        }
        removed = [
            address
            for address, entry in snapshot.entries.items()
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

    def _execute_workflow(
        self,
        *,
        workflow_address: str,
        payload: dict[str, Any],
        snapshot: RuntimeSnapshot,
    ) -> tuple[WorkflowExecutionState, list[WorkflowHistoryEvent], list[Diagnostic]]:
        execution_contract = payload.get("execution_contract", {})
        result_contract = payload.get("result_contract", {})
        observable_steps = result_contract.get("observable_steps", {})
        now = _coerce_iso_now()
        workflow_result = WorkflowExecutionState(
            state_schema_version=payload.get(
                "state_schema_version",
                execution_contract.get("state_schema_version", "workflow-step-state/v1"),
            ),
            workflow_status=WorkflowStatus.RUNNING,
            run_id=f"{workflow_address}-run",
            started_at=now,
            updated_at=now,
            steps={
                step_name: WorkflowStepExecutionState()
                for step_name in observable_steps
            },
        )
        history = [
            WorkflowHistoryEvent(
                event_type=WorkflowHistoryEventType.WORKFLOW_STARTED,
                timestamp=now,
                step_name=execution_contract.get("start_step"),
            )
        ]
        diagnostics: list[Diagnostic] = []

        control_steps = payload.get("control_steps", {})
        authored_steps = payload.get("spec", {}).get("steps", {})
        start_step = execution_contract.get("start_step", payload.get("start_step", ""))
        timeout_seconds = execution_contract.get("timeout_seconds")
        deadline = time.monotonic() + int(timeout_seconds) if timeout_seconds else None
        current = start_step
        visited: set[str] = set()

        while current:
            if current in visited:
                diagnostics.append(
                    _diag(
                        "docker.workflow-cycle",
                        workflow_address,
                        f"Workflow revisited step {current!r}; refusing to continue.",
                    )
                )
                return self._workflow_contract_failure(
                    workflow_result,
                    history,
                    workflow_address,
                    f"workflow revisited step {current!r}",
                    diagnostics,
                    current,
                )
            visited.add(current)

            if deadline is not None and time.monotonic() > deadline:
                result, mutated_history = self._terminalize_workflow(
                    workflow_result,
                    history,
                    WorkflowStatus.TIMED_OUT,
                    "workflow timed out",
                    current,
                )
                return result, mutated_history, diagnostics

            step = control_steps.get(current)
            if not isinstance(step, dict):
                diagnostics.append(
                    _diag(
                        "docker.workflow-step-missing",
                        workflow_address,
                        f"Workflow references unknown step {current!r}.",
                    )
                )
                return self._workflow_contract_failure(
                    workflow_result,
                    history,
                    workflow_address,
                    f"unknown step {current!r}",
                    diagnostics,
                    current,
                )

            step_type = step.get("step_type", "end")
            history.append(
                WorkflowHistoryEvent(
                    event_type=WorkflowHistoryEventType.STEP_STARTED,
                    timestamp=_coerce_iso_now(),
                    step_name=current,
                )
            )

            if current in workflow_result.steps:
                step_state = workflow_result.steps[current]
                workflow_result.steps[current] = WorkflowStepExecutionState(
                    lifecycle=WorkflowStepLifecycle.RUNNING,
                    attempts=step_state.attempts + 1,
                )

            if step_type == "end":
                if current in workflow_result.steps:
                    step_state = workflow_result.steps[current]
                    workflow_result.steps[current] = WorkflowStepExecutionState(
                        lifecycle=WorkflowStepLifecycle.COMPLETED,
                        outcome=WorkflowStepOutcome.SUCCEEDED,
                        attempts=max(step_state.attempts, 1),
                    )
                authored_step = authored_steps.get(current, {})
                description = str(
                    step.get("description")
                    or authored_step.get("description")
                    or "workflow completed"
                )
                workflow_result, history = self._terminalize_workflow(
                    workflow_result,
                    history,
                    WorkflowStatus.SUCCEEDED,
                    description,
                    current,
                )
                return workflow_result, history, diagnostics

            if step_type == "objective":
                objective_address = str(step.get("objective_address", ""))
                objective_ready, objective_success, objective_diag = self._objective_status(
                    objective_address,
                    snapshot,
                )
                if objective_diag is not None:
                    diagnostics.append(objective_diag)
                    return self._workflow_contract_failure(
                        workflow_result,
                        history,
                        workflow_address,
                        objective_diag.message,
                        diagnostics,
                        current,
                    )
                if not objective_ready:
                    diagnostics.append(
                        _diag(
                            "docker.workflow-objective-unready",
                            workflow_address,
                            f"Objective step {current!r} requires ready evaluation state for {objective_address!r}.",
                        )
                    )
                    return self._workflow_contract_failure(
                        workflow_result,
                        history,
                        workflow_address,
                        f"objective state for {objective_address!r} is not ready",
                        diagnostics,
                        current,
                    )

                outcome = "succeeded" if objective_success else "failed"
                if current in workflow_result.steps:
                    step_state = workflow_result.steps[current]
                    workflow_result.steps[current] = WorkflowStepExecutionState(
                        lifecycle=WorkflowStepLifecycle.COMPLETED,
                        outcome=(
                            WorkflowStepOutcome.SUCCEEDED
                            if objective_success
                            else WorkflowStepOutcome.FAILED
                        ),
                        attempts=max(step_state.attempts, 1),
                    )
                history.append(
                    WorkflowHistoryEvent(
                        event_type=WorkflowHistoryEventType.STEP_COMPLETED,
                        timestamp=_coerce_iso_now(),
                        step_name=current,
                        outcome=(
                            workflow_result.steps[current].outcome
                            if current in workflow_result.steps
                            else None
                        ),
                        details={"objective_address": objective_address},
                    )
                )
                next_step = step.get("on_success", "") if objective_success else step.get("on_failure", "")
                if not next_step:
                    status = WorkflowStatus.SUCCEEDED if objective_success else WorkflowStatus.FAILED
                    reason = (
                        f"Objective step {current} succeeded"
                        if objective_success
                        else f"Objective step {current} failed"
                    )
                    workflow_result, history = self._terminalize_workflow(
                        workflow_result,
                        history,
                        status,
                        reason,
                        current,
                    )
                    return workflow_result, history, diagnostics
                current = str(next_step)
                workflow_result = WorkflowExecutionState(
                    state_schema_version=workflow_result.state_schema_version,
                    workflow_status=workflow_result.workflow_status,
                    run_id=workflow_result.run_id,
                    started_at=workflow_result.started_at,
                    updated_at=_coerce_iso_now(),
                    terminal_reason=workflow_result.terminal_reason,
                    compensation_status=workflow_result.compensation_status,
                    compensation_started_at=workflow_result.compensation_started_at,
                    compensation_updated_at=workflow_result.compensation_updated_at,
                    compensation_failures=list(workflow_result.compensation_failures),
                    steps=dict(workflow_result.steps),
                )
                continue

            if step_type == "decision":
                predicate = step.get("predicate", {})
                decision_value, decision_diag = self._predicate_truth(predicate, snapshot, workflow_address)
                if decision_diag is not None:
                    diagnostics.append(decision_diag)
                    return self._workflow_contract_failure(
                        workflow_result,
                        history,
                        workflow_address,
                        decision_diag.message,
                        diagnostics,
                        current,
                    )
                if current in workflow_result.steps:
                    step_state = workflow_result.steps[current]
                    workflow_result.steps[current] = WorkflowStepExecutionState(
                        lifecycle=WorkflowStepLifecycle.COMPLETED,
                        outcome=WorkflowStepOutcome.SUCCEEDED,
                        attempts=max(step_state.attempts, 1),
                    )
                branch_name = "then" if decision_value else "else"
                history.append(
                    WorkflowHistoryEvent(
                        event_type=WorkflowHistoryEventType.STEP_COMPLETED,
                        timestamp=_coerce_iso_now(),
                        step_name=current,
                        branch_name=branch_name,
                        outcome=(
                            workflow_result.steps[current].outcome
                            if current in workflow_result.steps
                            else None
                        ),
                        details={"branch": branch_name},
                    )
                )
                next_step = step.get("then_step", "") if decision_value else step.get("else_step", "")
                if not next_step:
                    diagnostics.append(
                        _diag(
                            "docker.workflow-decision-branch-missing",
                            workflow_address,
                            f"Decision step {current!r} has no {branch_name!r} branch target.",
                        )
                    )
                    return self._workflow_contract_failure(
                        workflow_result,
                        history,
                        workflow_address,
                        f"decision step {current!r} is missing the {branch_name!r} branch",
                        diagnostics,
                        current,
                    )
                current = str(next_step)
                workflow_result = WorkflowExecutionState(
                    state_schema_version=workflow_result.state_schema_version,
                    workflow_status=workflow_result.workflow_status,
                    run_id=workflow_result.run_id,
                    started_at=workflow_result.started_at,
                    updated_at=_coerce_iso_now(),
                    terminal_reason=workflow_result.terminal_reason,
                    compensation_status=workflow_result.compensation_status,
                    compensation_started_at=workflow_result.compensation_started_at,
                    compensation_updated_at=workflow_result.compensation_updated_at,
                    compensation_failures=list(workflow_result.compensation_failures),
                    steps=dict(workflow_result.steps),
                )
                continue

            diagnostics.append(
                _diag(
                    "docker.workflow-step-unsupported",
                    workflow_address,
                    f"Docker reference backend does not support workflow step type {step_type!r}.",
                )
            )
            return self._workflow_contract_failure(
                workflow_result,
                history,
                workflow_address,
                f"unsupported workflow step type {step_type!r}",
                diagnostics,
                current,
            )

        diagnostics.append(
            _diag(
                "docker.workflow-no-terminal-step",
                workflow_address,
                "Workflow exited without reaching an end step.",
            )
        )
        return self._workflow_contract_failure(
            workflow_result,
            history,
            workflow_address,
            "workflow exited without reaching an end step",
            diagnostics,
            current or start_step,
        )

    def _workflow_contract_failure(
        self,
        workflow_result: WorkflowExecutionState,
        history: list[WorkflowHistoryEvent],
        workflow_address: str,
        reason: str,
        diagnostics: list[Diagnostic],
        step_name: str | None,
    ) -> tuple[WorkflowExecutionState, list[WorkflowHistoryEvent], list[Diagnostic]]:
        result, mutated_history = self._terminalize_workflow(
            workflow_result,
            history,
            WorkflowStatus.FAILED,
            reason,
            step_name,
        )
        return result, mutated_history, diagnostics

    def _terminalize_workflow(
        self,
        workflow_result: WorkflowExecutionState,
        history: list[WorkflowHistoryEvent],
        status: WorkflowStatus,
        reason: str,
        step_name: str | None,
    ) -> tuple[WorkflowExecutionState, list[WorkflowHistoryEvent]]:
        timestamp = _coerce_iso_now()
        event_type = {
            WorkflowStatus.SUCCEEDED: WorkflowHistoryEventType.WORKFLOW_COMPLETED,
            WorkflowStatus.FAILED: WorkflowHistoryEventType.WORKFLOW_FAILED,
            WorkflowStatus.CANCELLED: WorkflowHistoryEventType.WORKFLOW_CANCELLED,
            WorkflowStatus.TIMED_OUT: WorkflowHistoryEventType.WORKFLOW_TIMED_OUT,
        }[status]
        history.append(
            WorkflowHistoryEvent(
                event_type=event_type,
                timestamp=timestamp,
                step_name=step_name,
                details={"reason": reason},
            )
        )
        result = WorkflowExecutionState(
            state_schema_version=workflow_result.state_schema_version,
            workflow_status=status,
            run_id=workflow_result.run_id,
            started_at=workflow_result.started_at,
            updated_at=timestamp,
            terminal_reason=reason,
            compensation_status=workflow_result.compensation_status,
            compensation_started_at=workflow_result.compensation_started_at,
            compensation_updated_at=workflow_result.compensation_updated_at,
            compensation_failures=list(workflow_result.compensation_failures),
            steps=dict(workflow_result.steps),
        )
        return result, history

    def _objective_status(
        self,
        objective_address: str,
        snapshot: RuntimeSnapshot,
    ) -> tuple[bool, bool, Diagnostic | None]:
        state = self._evaluation_state(objective_address, snapshot)
        if state is None:
            return False, False, _diag(
                "docker.workflow-objective-missing",
                objective_address,
                f"No evaluation result exists for objective {objective_address!r}.",
            )
        if state.status != EvaluationResultStatus.READY:
            return False, False, None
        if state.passed is None:
            return False, False, _diag(
                "docker.workflow-objective-invalid",
                objective_address,
                f"Objective result {objective_address!r} is ready but did not report 'passed'.",
            )
        return True, state.passed, None

    def _predicate_truth(
        self,
        predicate: dict[str, Any],
        snapshot: RuntimeSnapshot,
        workflow_address: str,
    ) -> tuple[bool, Diagnostic | None]:
        if predicate.get("step_state_predicates"):
            return False, _diag(
                "docker.workflow-step-state-predicate-unsupported",
                workflow_address,
                "Docker reference backend does not support step-state workflow predicates.",
            )

        truth_values: list[bool] = []
        for key in (
            "condition_addresses",
            "evaluation_addresses",
            "tlo_addresses",
            "goal_addresses",
            "objective_addresses",
        ):
            for address in predicate.get(key, ()) or ():
                state = self._evaluation_state(str(address), snapshot)
                if state is None:
                    return False, _diag(
                        "docker.workflow-predicate-missing",
                        workflow_address,
                        f"Workflow predicate references {address!r}, but no evaluation result exists for it.",
                    )
                if state.status != EvaluationResultStatus.READY or state.passed is None:
                    return False, _diag(
                        "docker.workflow-predicate-unready",
                        workflow_address,
                        f"Workflow predicate requires ready passed/fail state for {address!r}.",
                    )
                truth_values.append(state.passed)

        for address in predicate.get("metric_addresses", ()) or ():
            state = self._evaluation_state(str(address), snapshot)
            if state is None:
                return False, _diag(
                    "docker.workflow-predicate-missing",
                    workflow_address,
                    f"Workflow predicate references metric {address!r}, but no evaluation result exists for it.",
                )
            if state.status != EvaluationResultStatus.READY or state.score is None:
                return False, _diag(
                    "docker.workflow-predicate-unready",
                    workflow_address,
                    f"Workflow predicate requires ready score state for metric {address!r}.",
                )
            truth_values.append(float(state.score) > 0)

        return any(truth_values), None

    def _evaluation_state(
        self,
        address: str,
        snapshot: RuntimeSnapshot,
    ) -> EvaluationExecutionState | None:
        payload = snapshot.evaluation_results.get(address)
        if not isinstance(payload, dict):
            return None
        try:
            return EvaluationExecutionState.from_payload(payload)
        except (TypeError, ValueError):
            return None


class DockerEvaluator:
    """Evaluate conditions and the scoring pipeline from runtime plans."""

    def __init__(self, provisioner: DockerProvisioner) -> None:
        self._provisioner = provisioner
        self._running = False
        self._startup_order: list[str] = []
        self._results: dict[str, dict[str, Any]] = {}
        self._history: dict[str, list[dict[str, Any]]] = {}

    def _get_client(self) -> Any:
        return self._provisioner._get_client()

    def start(
        self,
        plan: EvaluationPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        changed: list[str] = []
        diagnostics: list[Diagnostic] = []
        results = dict(snapshot.evaluation_results)
        history = {
            address: list(events)
            for address, events in snapshot.evaluation_history.items()
        }
        normalized_results: dict[str, EvaluationExecutionState] = {}
        for address, payload in results.items():
            if not isinstance(payload, dict):
                continue
            try:
                normalized_results[address] = EvaluationExecutionState.from_payload(payload)
            except (TypeError, ValueError):
                continue

        for op in _ordered_operations(plan.operations, plan.startup_order):
            if op.action == ChangeAction.DELETE:
                entries.pop(op.address, None)
                results.pop(op.address, None)
                history.pop(op.address, None)
                normalized_results.pop(op.address, None)
                changed.append(op.address)
                continue
            if op.action == ChangeAction.UNCHANGED:
                continue

            state, events, op_diagnostics = self._evaluate_operation(op, normalized_results)
            diagnostics.extend(op_diagnostics)
            normalized_results[op.address] = state
            results[op.address] = _result_payload(state)
            history[op.address] = _history_payloads(events)
            entries[op.address] = SnapshotEntry(
                address=op.address,
                domain=RuntimeDomain.EVALUATION,
                resource_type=op.resource_type,
                payload=op.payload,
                ordering_dependencies=op.ordering_dependencies,
                refresh_dependencies=op.refresh_dependencies,
                status=state.status.value,
            )
            changed.append(op.address)

        self._running = bool(plan.resources)
        self._startup_order = list(plan.startup_order)
        self._results = results
        self._history = history

        return ApplyResult(
            success=not any(diag.is_error for diag in diagnostics),
            snapshot=snapshot.with_entries(
                entries,
                evaluation_results=results,
                evaluation_history=history,
            ),
            changed_addresses=changed,
            diagnostics=diagnostics,
        )

    def _evaluate_operation(
        self,
        op: EvaluationOp,
        normalized_results: dict[str, EvaluationExecutionState],
    ) -> tuple[EvaluationExecutionState, list[EvaluationHistoryEvent], list[Diagnostic]]:
        now = _coerce_iso_now()
        resource_type = str(
            op.payload.get("result_contract", {}).get("resource_type", op.resource_type)
        )
        started_event = EvaluationHistoryEvent(
            event_type=EvaluationHistoryEventType.EVALUATION_STARTED,
            timestamp=now,
            status=EvaluationResultStatus.RUNNING,
            detail=f"docker evaluation for {op.address}",
        )

        try:
            state = self._evaluate_ready_state(op, resource_type, normalized_results, now)
            return (
                state,
                [
                    started_event,
                    EvaluationHistoryEvent(
                        event_type=EvaluationHistoryEventType.EVALUATION_READY,
                        timestamp=state.updated_at,
                        status=state.status,
                        passed=state.passed,
                        score=state.score,
                        max_score=state.max_score,
                        detail=state.detail,
                        evidence_refs=state.evidence_refs,
                    ),
                ],
                [],
            )
        except _EvaluationRuntimeError as exc:
            diagnostic = _diag(exc.code, op.address, exc.message)
            failed_state = EvaluationExecutionState(
                state_schema_version=op.payload.get("result_contract", {}).get(
                    "state_schema_version",
                    EVALUATION_STATE_SCHEMA_VERSION,
                ),
                resource_type=resource_type,
                run_id=f"docker-eval-{op.address}",
                status=EvaluationResultStatus.FAILED,
                observed_at=now,
                updated_at=_coerce_iso_now(),
                detail=exc.message,
            )
            return (
                failed_state,
                [
                    started_event,
                    EvaluationHistoryEvent(
                        event_type=EvaluationHistoryEventType.EVALUATION_FAILED,
                        timestamp=failed_state.updated_at,
                        status=failed_state.status,
                        detail=failed_state.detail,
                    ),
                ],
                [diagnostic],
            )

    def _evaluate_ready_state(
        self,
        op: EvaluationOp,
        resource_type: str,
        normalized_results: dict[str, EvaluationExecutionState],
        observed_at: str,
    ) -> EvaluationExecutionState:
        if resource_type == "condition-binding":
            passed = self._evaluate_condition(op)
            return EvaluationExecutionState(
                state_schema_version=EVALUATION_STATE_SCHEMA_VERSION,
                resource_type=resource_type,
                run_id=f"docker-eval-{op.address}",
                status=EvaluationResultStatus.READY,
                observed_at=observed_at,
                updated_at=_coerce_iso_now(),
                passed=passed,
                detail=f"condition evaluated for {op.address}",
            )

        if resource_type == "metric":
            spec = op.payload.get("spec", {})
            metric_type = str(spec.get("type", ""))
            if metric_type != "conditional":
                raise _EvaluationRuntimeError(
                    "docker.manual-metric-unsupported",
                    "Docker reference evaluator only supports conditional metrics.",
                )
            max_score = spec.get("max-score", spec.get("max_score"))
            if isinstance(max_score, bool) or not isinstance(max_score, int):
                raise _EvaluationRuntimeError(
                    "docker.metric-max-score-invalid",
                    f"Metric {op.address!r} has no valid integer max-score.",
                )
            condition_addresses = tuple(op.payload.get("condition_addresses", ()) or ())
            if not condition_addresses:
                raise _EvaluationRuntimeError(
                    "docker.metric-condition-missing",
                    f"Conditional metric {op.address!r} has no resolved condition address.",
                )
            condition_state = self._require_pass_result(
                str(condition_addresses[0]),
                normalized_results,
                "metric condition",
            )
            score = max_score if condition_state.passed else 0
            return EvaluationExecutionState(
                state_schema_version=EVALUATION_STATE_SCHEMA_VERSION,
                resource_type=resource_type,
                run_id=f"docker-eval-{op.address}",
                status=EvaluationResultStatus.READY,
                observed_at=observed_at,
                updated_at=_coerce_iso_now(),
                score=score,
                max_score=max_score,
                detail=f"metric derived from {condition_addresses[0]}",
            )

        if resource_type == "evaluation":
            spec = op.payload.get("spec", {})
            metric_addresses = tuple(op.payload.get("metric_addresses", ()) or ())
            metric_states = [
                self._require_score_result(address, normalized_results, "evaluation metric")
                for address in metric_addresses
            ]
            total_score = sum(float(metric.score or 0) for metric in metric_states)
            total_max = sum(int(metric.max_score or 0) for metric in metric_states)
            passed = self._meets_min_score(spec.get("min-score", spec.get("min_score")), total_score, total_max)
            return EvaluationExecutionState(
                state_schema_version=EVALUATION_STATE_SCHEMA_VERSION,
                resource_type=resource_type,
                run_id=f"docker-eval-{op.address}",
                status=EvaluationResultStatus.READY,
                observed_at=observed_at,
                updated_at=_coerce_iso_now(),
                passed=passed,
                detail=f"evaluation aggregated {len(metric_states)} metric(s)",
            )

        if resource_type == "tlo":
            evaluation_address = str(op.payload.get("evaluation_address", ""))
            evaluation_state = self._require_pass_result(
                evaluation_address,
                normalized_results,
                "TLO evaluation",
            )
            return EvaluationExecutionState(
                state_schema_version=EVALUATION_STATE_SCHEMA_VERSION,
                resource_type=resource_type,
                run_id=f"docker-eval-{op.address}",
                status=EvaluationResultStatus.READY,
                observed_at=observed_at,
                updated_at=_coerce_iso_now(),
                passed=evaluation_state.passed,
                detail=f"TLO derived from {evaluation_address}",
            )

        if resource_type == "goal":
            tlo_addresses = tuple(op.payload.get("tlo_addresses", ()) or ())
            tlo_states = [
                self._require_pass_result(address, normalized_results, "goal TLO")
                for address in tlo_addresses
            ]
            passed = all(bool(state.passed) for state in tlo_states)
            return EvaluationExecutionState(
                state_schema_version=EVALUATION_STATE_SCHEMA_VERSION,
                resource_type=resource_type,
                run_id=f"docker-eval-{op.address}",
                status=EvaluationResultStatus.READY,
                observed_at=observed_at,
                updated_at=_coerce_iso_now(),
                passed=passed,
                detail=f"goal aggregated {len(tlo_states)} TLO(s)",
            )

        if resource_type == "objective":
            spec = op.payload.get("spec", {})
            success_spec = spec.get("success", {})
            success_mode = str(success_spec.get("mode", "all_of"))
            success_addresses = tuple(op.payload.get("success_addresses", ()) or ())
            if not success_addresses:
                raise _EvaluationRuntimeError(
                    "docker.objective-success-missing",
                    f"Objective {op.address!r} has no resolved success addresses.",
                )
            truth_values = [
                self._success_value_for_address(address, normalized_results)
                for address in success_addresses
            ]
            if success_mode == "any_of":
                passed = any(truth_values)
            else:
                passed = all(truth_values)
            return EvaluationExecutionState(
                state_schema_version=EVALUATION_STATE_SCHEMA_VERSION,
                resource_type=resource_type,
                run_id=f"docker-eval-{op.address}",
                status=EvaluationResultStatus.READY,
                observed_at=observed_at,
                updated_at=_coerce_iso_now(),
                passed=passed,
                detail=f"objective evaluated with mode {success_mode}",
            )

        raise _EvaluationRuntimeError(
            "docker.evaluation-resource-unsupported",
            f"Unsupported evaluation resource type {resource_type!r}.",
        )

    def _evaluate_condition(self, op: EvaluationOp) -> bool:
        node_address = op.payload.get("node_address", "")
        container_id = self._provisioner.containers.get(node_address)
        if not container_id:
            raise _EvaluationRuntimeError(
                "docker.condition-target-missing",
                f"Condition target {node_address!r} does not have a provisioned container.",
            )

        spec = op.payload.get("spec", {})
        template = spec.get("template", {})
        command = template.get("command") or spec.get("command")
        if not command:
            raise _EvaluationRuntimeError(
                "docker.condition-command-missing",
                f"Condition {op.address!r} does not define a command.",
            )

        result = _exec_run(self._get_client(), container_id, str(command))
        return result.exit_code == 0

    def _require_pass_result(
        self,
        address: str,
        normalized_results: dict[str, EvaluationExecutionState],
        label: str,
    ) -> EvaluationExecutionState:
        state = normalized_results.get(address)
        if state is None:
            raise _EvaluationRuntimeError(
                "docker.evaluation-dependency-missing",
                f"{label} dependency {address!r} has no result.",
            )
        if state.status != EvaluationResultStatus.READY or state.passed is None:
            raise _EvaluationRuntimeError(
                "docker.evaluation-dependency-unready",
                f"{label} dependency {address!r} is not ready with a passed/fail value.",
            )
        return state

    def _require_score_result(
        self,
        address: str,
        normalized_results: dict[str, EvaluationExecutionState],
        label: str,
    ) -> EvaluationExecutionState:
        state = normalized_results.get(address)
        if state is None:
            raise _EvaluationRuntimeError(
                "docker.evaluation-dependency-missing",
                f"{label} dependency {address!r} has no result.",
            )
        if state.status != EvaluationResultStatus.READY or state.score is None or state.max_score is None:
            raise _EvaluationRuntimeError(
                "docker.evaluation-dependency-unready",
                f"{label} dependency {address!r} is not ready with score/max_score values.",
            )
        return state

    def _success_value_for_address(
        self,
        address: str,
        normalized_results: dict[str, EvaluationExecutionState],
    ) -> bool:
        state = normalized_results.get(address)
        if state is None:
            raise _EvaluationRuntimeError(
                "docker.objective-success-missing",
                f"Objective success dependency {address!r} has no result.",
            )
        if state.status != EvaluationResultStatus.READY:
            raise _EvaluationRuntimeError(
                "docker.objective-success-unready",
                f"Objective success dependency {address!r} is not ready.",
            )
        if state.passed is not None:
            return state.passed
        if state.score is not None:
            return float(state.score) > 0
        raise _EvaluationRuntimeError(
            "docker.objective-success-invalid",
            f"Objective success dependency {address!r} did not expose passed or score data.",
        )

    def _meets_min_score(
        self,
        min_score_spec: dict[str, Any] | None,
        total_score: float,
        total_max: int,
    ) -> bool:
        if not isinstance(min_score_spec, dict):
            raise _EvaluationRuntimeError(
                "docker.evaluation-threshold-invalid",
                "Evaluation min-score threshold is missing or invalid.",
            )
        absolute = min_score_spec.get("absolute")
        percentage = min_score_spec.get("percentage")
        if isinstance(absolute, int) and not isinstance(absolute, bool):
            return total_score >= absolute
        if isinstance(percentage, int) and not isinstance(percentage, bool):
            if total_max <= 0:
                return False
            return (total_score / total_max) * 100 >= percentage
        raise _EvaluationRuntimeError(
            "docker.evaluation-threshold-invalid",
            "Evaluation min-score threshold must define absolute or percentage.",
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
            address: list(events)
            for address, events in self._history.items()
        }

    def stop(self, snapshot: RuntimeSnapshot) -> ApplyResult:
        entries = {
            address: entry
            for address, entry in snapshot.entries.items()
            if entry.domain != RuntimeDomain.EVALUATION
        }
        removed = [
            address
            for address, entry in snapshot.entries.items()
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


@dataclass(frozen=True)
class _EvaluationRuntimeError(Exception):
    code: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


def create_docker_components(
    *,
    manifest: BackendManifest,
    **config: Any,
) -> RuntimeTargetComponents:
    """Factory for Docker runtime components."""

    if config.get("scenario") is not None:
        raise ValueError(
            "Docker backend no longer accepts raw SDL scenario payloads. "
            "Use compiled runtime plans and snapshot state only."
        )

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

    if config.get("scenario") is not None:
        raise ValueError(
            "Docker backend no longer accepts raw SDL scenario payloads. "
            "Use compiled runtime plans and snapshot state only."
        )

    manifest = create_docker_manifest(**config)
    components = create_docker_components(manifest=manifest, **config)
    return RuntimeTarget(
        name="docker",
        manifest=manifest,
        provisioner=components.provisioner,
        orchestrator=components.orchestrator,
        evaluator=components.evaluator,
    )
