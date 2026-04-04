"""Docker backend — provisions scenarios via Docker Compose and the Docker SDK.

Implements the Provisioner, Orchestrator, and Evaluator runtime protocols.
The provisioner generates a ``docker-compose.yml`` from the provisioning plan
and brings the stack up with ``docker compose up``.  Post-compose operations
(account creation, content placement, SSH key distribution) and all runtime
commands (workflow execution, condition evaluation) use the Docker SDK for
Python (``docker.containers.get(name).exec_run(...)``).

Capability surface:
- Provisioner: vm + switch nodes on linux, file + directory content,
  accounts with password auth, SSH feature provisioning
- Orchestrator: workflows with timeouts, decision, retry, failure-transitions
- Evaluator: conditions, objectives, full scoring pipeline
"""

from __future__ import annotations

import logging
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

try:
    import docker as docker_sdk
except ImportError:  # pragma: no cover – optional dependency
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
# Lightweight result type (replaces subprocess.CompletedProcess)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ExecResult:
    """Result of a command executed inside a container."""
    exit_code: int
    output: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _diag(code: str, address: str, message: str, severity: Severity = Severity.ERROR) -> Diagnostic:
    return Diagnostic(code=code, domain="docker", address=address, message=message, severity=severity)


def _get_docker_client() -> Any:
    """Create a Docker SDK client, deferring the daemon probe."""
    if docker_sdk is None:
        raise RuntimeError(
            "The 'docker' Python package is required for the Docker backend. "
            "Install it with: pip install 'docker>=7.0.0'"
        )
    return docker_sdk.DockerClient.from_env()


def _exec_run(client: Any, container_id: str, cmd: list[str] | str, timeout: int = 120) -> ExecResult:
    """Execute a command in a running container via the Docker SDK."""
    container = client.containers.get(container_id)
    if isinstance(cmd, str):
        cmd = ["sh", "-c", cmd]
    exit_code, output = container.exec_run(cmd, demux=False)
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else (output or "")
    return ExecResult(exit_code=exit_code, output=text)


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
            supported_content_types=frozenset({"file", "directory"}),
            supported_account_features=frozenset(
                {"groups", "shell", "home", "auth_method"}
            ),
            max_total_nodes=20,
            supports_acls=False,
            supports_accounts=True,
        ),
        orchestrator=OrchestratorCapabilities(
            name="docker-orchestrator",
            supported_sections=frozenset(
                {"injects", "events", "scripts", "stories", "workflows"}
            ),
            supports_workflows=True,
            supports_condition_refs=True,
            supports_inject_bindings=True,
            supported_workflow_features=frozenset({
                WorkflowFeature.TIMEOUTS,
                WorkflowFeature.FAILURE_TRANSITIONS,
                WorkflowFeature.DECISION,
                WorkflowFeature.RETRY,
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
    """Provisions Docker networks and containers from SDL plans.

    Generates a ``docker-compose.yml`` for the infrastructure layer (networks
    and node containers) and brings it up with ``docker compose up -d``.
    Post-compose operations — content placement, account creation, feature
    bindings, and SSH key distribution — are performed via the Docker SDK.
    """

    def __init__(
        self,
        *,
        project_prefix: str = "aptl",
        use_ssh_image: bool = False,
    ) -> None:
        self._prefix = project_prefix
        self._use_ssh_image = use_ssh_image
        self._networks: dict[str, str] = {}   # address -> docker network id
        self._containers: dict[str, str] = {}  # address -> docker container id
        self._node_names: dict[str, str] = {}  # address -> node SDL name
        self._accounts: dict[str, dict[str, Any]] = {}  # address -> account spec
        self._compose_dir: Path | None = None
        self._client: Any = None  # Docker SDK client, created lazily
        self._ssh_pubkey: str = ""

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
        """Return container ID for a node by its SDL name."""
        for addr, name in self._node_names.items():
            if name == node_name:
                return self._containers.get(addr)
        return None

    def password_for_account(self, account_name: str) -> str | None:
        """Return the provisioned password for an account by address or name."""
        for addr, spec in self._accounts.items():
            if addr.endswith(f".{account_name}") or spec.get("username") == account_name:
                strength = spec.get("password_strength", "medium")
                if strength == "weak":
                    return "password123"
                elif strength == "strong":
                    return "Str0ng!P@ssw0rd#2024-Kali"
                return "m3dium_P@ss"
        return None

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

    # ------------------------------------------------------------------
    # apply — Compose for infra, SDK for post-compose ops
    # ------------------------------------------------------------------

    def apply(
        self,
        plan: ProvisioningPlan,
        snapshot: RuntimeSnapshot,
    ) -> ApplyResult:
        entries = dict(snapshot.entries)
        changed: list[str] = []
        diagnostics: list[Diagnostic] = []

        # Separate operations into compose-managed (networks, nodes) and
        # post-compose (content, accounts, features, conditions).
        compose_ops = []
        post_ops = []

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

            if op.resource_type in ("network", "node"):
                compose_ops.append(op)
            else:
                post_ops.append(op)

        # Phase 1: bring up networks + nodes via Compose
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
                for op in compose_ops:
                    diagnostics.append(
                        _diag("docker.compose-failed", op.address, str(exc))
                    )
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

        # Phase 2: post-compose operations via Docker SDK
        for op in post_ops:
            try:
                self._create_resource(
                    op.address, op.resource_type, op.payload,
                    ordering_dependencies=op.ordering_dependencies,
                )
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

    # ------------------------------------------------------------------
    # Compose generation and lifecycle
    # ------------------------------------------------------------------

    def _compose_up(self, ops: list[Any]) -> None:
        """Generate docker-compose.yml and bring the stack up.

        When there are no node/service ops (network-only), creates networks
        directly via the Docker SDK since ``docker compose up`` requires at
        least one service.
        """
        network_ops = [op for op in ops if op.resource_type == "network"]
        node_ops = [op for op in ops if op.resource_type == "node"]

        # Network-only: create via Docker SDK directly
        if network_ops and not node_ops:
            self._create_networks_directly(network_ops)
            return

        compose: dict[str, Any] = {"services": {}, "networks": {}}

        for op in network_ops:
            spec = op.payload.get("spec", {})
            properties = spec.get("properties")
            net_name = op.address.replace(".", "-")

            net_def: dict[str, Any] = {"driver": "bridge"}
            if isinstance(properties, dict):
                cidr = properties.get("cidr", "")
                gateway = properties.get("gateway", "")
                if cidr:
                    ipam_config: dict[str, str] = {"subnet": cidr}
                    if gateway:
                        ipam_config["gateway"] = gateway
                    net_def["ipam"] = {"config": [ipam_config]}

            compose["networks"][net_name] = net_def

        # Collect node/service definitions
        for op in node_ops:
            spec = op.payload.get("spec", {})
            source = spec.get("source", {})
            image_name = source.get("name", "ubuntu")
            image_version = source.get("version", "latest")
            if image_version == "*":
                image_version = "latest"

            if self._use_ssh_image:
                image = "panubo/sshd:latest"
            else:
                image = f"{image_name}:{image_version}"

            node_name = op.payload.get("node_name", op.address.split(".")[-1])
            container_name = f"{self._prefix}-{node_name}"

            service: dict[str, Any] = {
                "image": image,
                "container_name": container_name,
                "hostname": node_name,
            }

            if self._use_ssh_image and image.startswith("panubo/sshd"):
                service["environment"] = {
                    "SSH_ENABLE_PASSWORD_AUTH": "true",
                    "SSH_ENABLE_ROOT": "true",
                }
            else:
                service["command"] = "sleep infinity"

            # Attach to networks with aliases.  Networks may be defined in
            # this compose file OR already exist from an earlier apply() call
            # (created directly via Docker SDK).
            network_deps: list[str] = []
            for dep in op.ordering_dependencies:
                dep_key = dep.replace(".", "-")
                if dep_key in compose["networks"]:
                    network_deps.append(dep_key)
                elif dep in self._networks:
                    # Network already exists — reference it as external
                    ext_name = f"{self._prefix}-{dep_key}"
                    compose["networks"][dep_key] = {
                        "external": True,
                        "name": ext_name,
                    }
                    network_deps.append(dep_key)

            if network_deps:
                service["networks"] = {}
                for net_key in network_deps:
                    service["networks"][net_key] = {"aliases": [node_name]}

            compose["services"][node_name] = service
            # Pre-register the node name mapping so post-compose ops can find it
            self._node_names[op.address] = node_name

        # Remove empty sections
        if not compose["networks"]:
            del compose["networks"]
        if not compose["services"]:
            del compose["services"]

        # Write compose file and bring stack up
        self._compose_dir = Path(tempfile.mkdtemp(prefix=f"{self._prefix}-compose-"))
        compose_path = self._compose_dir / "docker-compose.yml"
        compose_path.write_text(yaml.dump(compose, default_flow_style=False, sort_keys=False))

        logger.info("docker: compose file written to %s", compose_path)

        subprocess.run(
            ["docker", "compose", "-f", str(compose_path),
             "-p", self._prefix, "up", "-d", "--wait"],
            check=True, capture_output=True, text=True, timeout=180,
        )
        logger.info("docker: compose stack '%s' is up", self._prefix)

        # Populate internal state from running containers
        client = self._get_client()
        for op in network_ops:
            net_name = f"{self._prefix}_{op.address.replace('.', '-')}"
            try:
                net = client.networks.get(net_name)
                self._networks[op.address] = net.id
            except Exception:
                # Compose may use a different naming scheme
                self._networks[op.address] = net_name

        for op in node_ops:
            node_name = op.payload.get("node_name", op.address.split(".")[-1])
            container_name = f"{self._prefix}-{node_name}"
            try:
                container = client.containers.get(container_name)
                self._containers[op.address] = container.id
            except Exception:
                logger.warning("docker: container %s not found after compose up", container_name)

    def _create_networks_directly(self, network_ops: list[Any]) -> None:
        """Create networks via Docker SDK when no services are needed."""
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

            ipam_config = docker_sdk.types.IPAMConfig(pool_configs=ipam_pool_configs) if ipam_pool_configs else None
            net = client.networks.create(name, driver="bridge", ipam=ipam_config)
            self._networks[op.address] = net.id
            logger.info("docker: created network %s (%s)", name, net.id[:12])

    # ------------------------------------------------------------------
    # Post-compose resource creation (via Docker SDK)
    # ------------------------------------------------------------------

    def _create_resource(
        self,
        address: str,
        resource_type: str,
        payload: dict[str, Any],
        ordering_dependencies: tuple[str, ...] = (),
    ) -> None:
        if resource_type == "content-placement":
            self._create_content(address, payload)
        elif resource_type == "account-placement":
            self._create_account(address, payload)
        elif resource_type == "feature-binding":
            self._create_feature_binding(address, payload)
        elif resource_type == "condition-binding":
            pass  # conditions are evaluated at runtime, not provisioned
        else:
            logger.warning("docker: skipping unknown resource type %s", resource_type)

    def _destroy_resource(self, address: str, resource_type: str) -> None:
        if resource_type == "network":
            net_id = self._networks.pop(address, None)
            if net_id:
                try:
                    client = self._get_client()
                    client.networks.get(net_id).remove()
                except Exception:
                    pass
        elif resource_type == "node":
            cid = self._containers.pop(address, None)
            if cid:
                try:
                    client = self._get_client()
                    client.containers.get(cid).remove(force=True)
                except Exception:
                    pass

    def _create_content(self, address: str, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        target_node = payload.get("target_node", "")
        target_address = payload.get("target_address", "")
        content_type = spec.get("type", "file")

        cid = self._containers.get(target_address)
        if not cid:
            logger.warning("docker: no container for content target %s", target_address)
            return

        client = self._get_client()

        if content_type == "directory":
            destination = spec.get("destination", "")
            if destination:
                _exec_run(client, cid, ["mkdir", "-p", destination])
                logger.info("docker: created directory %s:%s", target_node, destination)
            return

        # File content
        path = spec.get("path", "")
        text = spec.get("text")
        if not path or text is None:
            return

        parent = "/".join(path.split("/")[:-1])
        if parent:
            _exec_run(client, cid, ["mkdir", "-p", parent])
        # Use printf to avoid shell injection (text is escaped)
        _exec_run(client, cid, ["sh", "-c", f"printf '%s\\n' {shlex.quote(text)} > {shlex.quote(path)}"])
        logger.info("docker: placed content at %s:%s", target_node, path)

    def _create_feature_binding(self, address: str, payload: dict[str, Any]) -> None:
        """Provision a feature binding — install real software in a container."""
        feature_name = payload.get("feature_name", "")
        target_address = payload.get("node_address", "")
        node_name = payload.get("node_name", "")

        cid = self._containers.get(target_address)
        if not cid:
            logger.warning("docker: no container for feature target %s", target_address)
            return

        if feature_name == "ssh-password-auth":
            if self._use_ssh_image:
                logger.info("docker: ssh-password-auth on %s handled by image", node_name)
            else:
                self._install_ssh_server(cid, node_name)
        elif feature_name == "kali-tools":
            self._install_ssh_client_tools(cid, node_name)
        else:
            logger.info(
                "docker: feature %s on %s has no provisioning action",
                feature_name, node_name,
            )

    def _install_ssh_server(self, cid: str, node_name: str) -> None:
        """Ensure OpenSSH server is running and configured in a container."""
        logger.info("docker: ensuring sshd on %s", node_name)
        client = self._get_client()

        check = _exec_run(client, cid, ["which", "sshd"])
        if check.exit_code == 0:
            _exec_run(client, cid, "pgrep sshd >/dev/null 2>&1 || /usr/sbin/sshd")
            logger.info("docker: sshd already present on %s", node_name)
            return

        _exec_run(
            client, cid,
            "apt-get update -qq 2>/dev/null"
            " && DEBIAN_FRONTEND=noninteractive"
            " apt-get install -y -qq openssh-server netcat-openbsd"
            " 2>/dev/null 1>/dev/null"
            " && mkdir -p /run/sshd"
            " && sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
            " && sed -i 's/#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config"
            " && /usr/sbin/sshd",
        )
        logger.info("docker: sshd installed and running on %s", node_name)

    def _install_ssh_client_tools(self, cid: str, node_name: str) -> None:
        """Ensure SSH client tools and generate an ed25519 key pair."""
        logger.info("docker: ensuring ssh client on %s", node_name)
        client = self._get_client()

        _exec_run(
            client, cid,
            "mkdir -p /root/.ssh"
            " && test -f /root/.ssh/id_ed25519"
            " || ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N '' -q",
        )
        result = _exec_run(client, cid, ["cat", "/root/.ssh/id_ed25519.pub"])
        if result.exit_code == 0 and result.output.strip():
            self._ssh_pubkey = result.output.strip()
            logger.info("docker: ssh key generated on %s", node_name)

    def wait_for_ssh(self, timeout: int = 30) -> None:
        """Wait for sshd to be listening on all SSH-enabled containers."""
        if not self._use_ssh_image:
            return
        client = self._get_client()
        deadline = time.monotonic() + timeout
        for address, cid in self._containers.items():
            while time.monotonic() < deadline:
                check = _exec_run(client, cid, "pgrep -x sshd >/dev/null 2>&1")
                if check.exit_code == 0:
                    break
                time.sleep(0.5)

    def distribute_ssh_keys(self) -> None:
        """Copy the operator's public key to all containers that have sshd."""
        if not self._ssh_pubkey:
            return

        client = self._get_client()
        pubkey = shlex.quote(self._ssh_pubkey)

        for address, cid in self._containers.items():
            for acct_addr, acct_spec in self._accounts.items():
                node_name = acct_spec.get("node_name", "")
                container_node = self._node_names.get(address, "")
                if node_name != container_node:
                    continue

                username = acct_spec.get("username", "")
                home = acct_spec.get("home", f"/home/{username}")
                _exec_run(
                    client, cid,
                    f"mkdir -p {home}/.ssh"
                    f" && echo {pubkey} >> {home}/.ssh/authorized_keys"
                    f" && chmod 700 {home}/.ssh"
                    f" && chmod 600 {home}/.ssh/authorized_keys"
                    f" && chown -R {username}:{username} {home}/.ssh 2>/dev/null || true",
                )

        # Copy private key from kali to intermediate hop nodes
        kali_cid = ""
        for addr, name in self._node_names.items():
            if name == "kali":
                kali_cid = self._containers.get(addr, "")
                break

        if kali_cid:
            priv_result = _exec_run(client, kali_cid, ["cat", "/root/.ssh/id_ed25519"])
            if priv_result.exit_code == 0 and priv_result.output.strip():
                priv_key = shlex.quote(priv_result.output.strip())
                for address, cid in self._containers.items():
                    if cid == kali_cid:
                        continue
                    for acct_addr, acct_spec in self._accounts.items():
                        node_name = acct_spec.get("node_name", "")
                        container_node = self._node_names.get(address, "")
                        if node_name != container_node:
                            continue
                        username = acct_spec.get("username", "")
                        home = acct_spec.get("home", f"/home/{username}")
                        _exec_run(
                            client, cid,
                            f"mkdir -p {home}/.ssh"
                            f" && printf '%s\\n' {priv_key} > {home}/.ssh/id_ed25519"
                            f" && chmod 600 {home}/.ssh/id_ed25519"
                            f" && chown -R {username}:{username} {home}/.ssh 2>/dev/null || true",
                        )

        logger.info("docker: SSH keys distributed to all containers")

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

        client = self._get_client()
        groups = spec.get("groups", [])
        shell = spec.get("shell", "/bin/bash")
        home = spec.get("home", f"/home/{username}")
        password_strength = spec.get("password_strength", "medium")

        if password_strength == "weak":
            password = "password123"
        elif password_strength == "strong":
            password = "Str0ng!P@ssw0rd#2024-Kali"
        else:
            password = "m3dium_P@ss"

        _exec_run(
            client, cid,
            f"id {shlex.quote(username)} 2>/dev/null || "
            f"useradd -m -d {shlex.quote(home)} -s {shlex.quote(shell)} {shlex.quote(username)} 2>/dev/null || "
            f"adduser -D -h {shlex.quote(home)} -s {shlex.quote(shell)} {shlex.quote(username)} 2>/dev/null || true",
        )

        _exec_run(
            client, cid,
            f"echo {shlex.quote(username + ':' + password)} | chpasswd 2>/dev/null || true",
        )

        for group in groups:
            _exec_run(
                client, cid,
                f"(groupadd {shlex.quote(group)} 2>/dev/null || addgroup {shlex.quote(group)} 2>/dev/null || true)"
                f" && (usermod -aG {shlex.quote(group)} {shlex.quote(username)} 2>/dev/null"
                f" || addgroup {shlex.quote(username)} {shlex.quote(group)} 2>/dev/null || true)",
            )

        self._accounts[address] = {**spec, "node_name": node_name}
        logger.info("docker: created account %s on %s", username, node_name)

    def cleanup(self) -> None:
        """Tear down the compose stack and clean up all resources."""
        # Compose down removes compose-managed containers and networks
        if self._compose_dir and (self._compose_dir / "docker-compose.yml").exists():
            subprocess.run(
                ["docker", "compose", "-f",
                 str(self._compose_dir / "docker-compose.yml"),
                 "-p", self._prefix, "down", "-v", "--remove-orphans"],
                check=False, capture_output=True, text=True, timeout=60,
            )
            logger.info("docker: compose stack '%s' torn down", self._prefix)

        # Remove any remaining resources not managed by compose
        # (e.g. networks created directly via SDK, or compose wasn't used)
        if self._client:
            for address, cid in list(self._containers.items()):
                try:
                    self._client.containers.get(cid).remove(force=True)
                except Exception:
                    pass
            for address, net_id in list(self._networks.items()):
                try:
                    self._client.networks.get(net_id).remove()
                except Exception:
                    pass

        self._containers.clear()
        self._networks.clear()


# ---------------------------------------------------------------------------
# Docker Orchestrator
# ---------------------------------------------------------------------------

class DockerOrchestrator:
    """Executes workflow steps inside Docker containers.

    When a parsed SDL scenario is provided, the orchestrator eagerly walks
    each workflow's step graph and performs real actions (SSH between
    containers, read files, check conditions) using the Docker SDK.
    Without a scenario it falls back to bookkeeping-only mode for unit tests.
    """

    def __init__(
        self,
        provisioner: DockerProvisioner | None = None,
        scenario: dict[str, Any] | None = None,
    ) -> None:
        self._provisioner = provisioner
        self._scenario = scenario
        self._running = False
        self._startup_order: list[str] = []
        self._results: dict[str, dict[str, Any]] = {}
        self._history: dict[str, list[dict[str, Any]]] = {}
        self.captured_flags: dict[str, str] = {}

    def _get_client(self) -> Any:
        if self._provisioner:
            return self._provisioner._get_client()
        return _get_docker_client()

    # ------------------------------------------------------------------
    # Protocol methods
    # ------------------------------------------------------------------

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
                wf_result: dict[str, Any] = {
                    "state_schema_version": result_contract.get(
                        "state_schema_version",
                        op.payload.get("state_schema_version", "workflow-step-state/v1"),
                    ),
                    "workflow_status": "running",
                    "run_id": f"{op.address}-run",
                    "started_at": now,
                    "updated_at": now,
                    "terminal_reason": None,
                    "compensation_status": "not_required",
                    "compensation_failures": [],
                    "steps": step_states,
                }
                wf_history: list[dict[str, Any]] = [{
                    "event_type": "workflow_started",
                    "timestamp": now,
                    "step_name": op.payload.get("execution_contract", {}).get("start_step"),
                    "branch_name": None,
                    "join_step": None,
                    "outcome": None,
                    "details": {},
                }]

                if self._provisioner and self._scenario:
                    try:
                        self._execute_workflow(op.payload, wf_result, wf_history)
                    except Exception as exc:
                        logger.error("docker: workflow execution failed: %s", exc)
                        wf_result["workflow_status"] = "failed"
                        wf_result["terminal_reason"] = str(exc)
                        wf_result["updated_at"] = _utc_now()

                results[op.address] = wf_result
                history[op.address] = wf_history

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

    # ------------------------------------------------------------------
    # Workflow execution engine
    # ------------------------------------------------------------------

    def _execute_workflow(
        self,
        payload: dict[str, Any],
        wf_result: dict[str, Any],
        wf_history: list[dict[str, Any]],
    ) -> None:
        """Eagerly walk the step graph and execute each step."""
        control_steps = payload.get("control_steps", {})
        exec_contract = payload.get("execution_contract", {})
        start_step = exec_contract.get("start_step", payload.get("start_step", ""))
        timeout_seconds = exec_contract.get("timeout_seconds")
        deadline = time.monotonic() + (int(timeout_seconds) if timeout_seconds else 600)

        current = start_step
        visited: set[str] = set()

        while current and current not in visited:
            if time.monotonic() > deadline:
                wf_result["workflow_status"] = "timed_out"
                wf_result["terminal_reason"] = "workflow timed out"
                wf_result["updated_at"] = _utc_now()
                wf_history.append({
                    "event_type": "workflow_timed_out",
                    "timestamp": _utc_now(),
                    "step_name": current,
                    "branch_name": None, "join_step": None,
                    "outcome": None, "details": {},
                })
                return

            visited.add(current)
            step = control_steps.get(current)
            if not step:
                logger.warning("docker: workflow step %s not found", current)
                break

            step_type = step.get("step_type", "end")
            now = _utc_now()

            if step_type == "end":
                step_name = current
                if step_name in wf_result.get("steps", {}):
                    wf_result["steps"][step_name]["lifecycle"] = "completed"
                    wf_result["steps"][step_name]["outcome"] = "succeeded"
                desc = step.get("description", "workflow completed")
                wf_result["workflow_status"] = "succeeded"
                wf_result["terminal_reason"] = desc
                wf_result["updated_at"] = now
                wf_history.append({
                    "event_type": "step_completed",
                    "timestamp": now,
                    "step_name": current,
                    "branch_name": None, "join_step": None,
                    "outcome": "succeeded",
                    "details": {"description": desc},
                })
                wf_history.append({
                    "event_type": "workflow_completed",
                    "timestamp": now,
                    "step_name": current,
                    "branch_name": None, "join_step": None,
                    "outcome": "succeeded",
                    "details": {"reason": desc},
                })
                return

            elif step_type == "objective":
                success = self._execute_objective_step(step, wf_result, wf_history, current)
                if success:
                    current = step.get("on_success", "")
                else:
                    current = step.get("on_failure", "")

            elif step_type == "decision":
                branch = self._execute_decision_step(step, wf_result, wf_history, current)
                current = branch

            elif step_type == "retry":
                success = self._execute_retry_step(step, wf_result, wf_history, current)
                if success:
                    current = step.get("on_success", "")
                else:
                    current = step.get("on_exhausted", step.get("on_failure", ""))

            else:
                logger.warning("docker: unhandled step type %s", step_type)
                break

        if wf_result.get("workflow_status") == "running":
            wf_result["workflow_status"] = "failed"
            wf_result["terminal_reason"] = "step graph exhausted without reaching end step"
            wf_result["updated_at"] = _utc_now()

    def _execute_objective_step(
        self,
        step: dict[str, Any],
        wf_result: dict[str, Any],
        wf_history: list[dict[str, Any]],
        step_name: str,
    ) -> bool:
        objective_address = step.get("objective_address", "")
        obj_name = objective_address.rsplit(".", 1)[-1] if objective_address else ""
        now = _utc_now()

        if step_name in wf_result.get("steps", {}):
            wf_result["steps"][step_name]["lifecycle"] = "running"
            wf_result["steps"][step_name]["attempts"] = (
                wf_result["steps"][step_name].get("attempts", 0) + 1
            )

        success = self._run_objective(obj_name)
        outcome = "succeeded" if success else "failed"

        if step_name in wf_result.get("steps", {}):
            wf_result["steps"][step_name]["lifecycle"] = "completed"
            wf_result["steps"][step_name]["outcome"] = outcome
        wf_result["updated_at"] = _utc_now()

        wf_history.append({
            "event_type": "step_completed",
            "timestamp": now,
            "step_name": step_name,
            "branch_name": None, "join_step": None,
            "outcome": outcome,
            "details": {"objective": obj_name},
        })
        return success

    def _execute_decision_step(
        self,
        step: dict[str, Any],
        wf_result: dict[str, Any],
        wf_history: list[dict[str, Any]],
        step_name: str,
    ) -> str:
        predicate = step.get("predicate", {})
        condition_addrs = predicate.get("condition_addresses", [])
        if not isinstance(condition_addrs, (list, tuple)):
            condition_addrs = []

        condition_met = False
        for cond_addr in condition_addrs:
            if self._check_condition_by_address(cond_addr):
                condition_met = True
                break

        branch = step.get("then_step", "") if condition_met else step.get("else_step", "")

        if step_name in wf_result.get("steps", {}):
            wf_result["steps"][step_name]["lifecycle"] = "completed"
            wf_result["steps"][step_name]["outcome"] = "succeeded"
        wf_result["updated_at"] = _utc_now()

        wf_history.append({
            "event_type": "step_completed",
            "timestamp": _utc_now(),
            "step_name": step_name,
            "branch_name": "then" if condition_met else "else",
            "join_step": None,
            "outcome": "succeeded",
            "details": {"condition_met": condition_met, "branch": "then" if condition_met else "else"},
        })
        return branch

    def _execute_retry_step(
        self,
        step: dict[str, Any],
        wf_result: dict[str, Any],
        wf_history: list[dict[str, Any]],
        step_name: str,
    ) -> bool:
        objective_address = step.get("objective_address", "")
        obj_name = objective_address.rsplit(".", 1)[-1] if objective_address else ""
        max_attempts = int(step.get("max_attempts", 3))

        for attempt in range(1, max_attempts + 1):
            if step_name in wf_result.get("steps", {}):
                wf_result["steps"][step_name]["lifecycle"] = "running"
                wf_result["steps"][step_name]["attempts"] = attempt

            success = self._run_objective(obj_name)

            wf_history.append({
                "event_type": "step_completed",
                "timestamp": _utc_now(),
                "step_name": step_name,
                "branch_name": None, "join_step": None,
                "outcome": "succeeded" if success else "failed",
                "details": {"attempt": attempt, "max_attempts": max_attempts},
            })

            if success:
                if step_name in wf_result.get("steps", {}):
                    wf_result["steps"][step_name]["lifecycle"] = "completed"
                    wf_result["steps"][step_name]["outcome"] = "succeeded"
                wf_result["updated_at"] = _utc_now()
                return True

        if step_name in wf_result.get("steps", {}):
            wf_result["steps"][step_name]["lifecycle"] = "completed"
            wf_result["steps"][step_name]["outcome"] = "exhausted"
        wf_result["updated_at"] = _utc_now()
        return False

    # ------------------------------------------------------------------
    # Action execution helpers
    # ------------------------------------------------------------------

    def _run_objective(self, objective_name: str) -> bool:
        if not self._provisioner or not self._scenario:
            return True  # bookkeeping mode

        objectives = self._scenario.get("objectives", {})
        obj_spec = objectives.get(objective_name, {})
        if not obj_spec:
            logger.warning("docker: objective %s not found in scenario", objective_name)
            return False

        agent_name = obj_spec.get("agent", "")
        targets = obj_spec.get("targets", [])
        actions = obj_spec.get("actions", [])

        agents = self._scenario.get("agents", {})
        agent_spec = agents.get(agent_name, {})
        starting_accounts = agent_spec.get("starting_accounts", [])

        accounts = self._scenario.get("accounts", {})
        agent_node = ""
        for acct_name in starting_accounts:
            acct = accounts.get(acct_name, {})
            if acct.get("node"):
                agent_node = acct["node"]
                break

        agent_cid = self._provisioner.container_for_node(agent_node)
        if not agent_cid:
            logger.warning("docker: no container for agent node %s", agent_node)
            return False

        if "read-file" in actions:
            return self._execute_read_file_objective(
                agent_cid, agent_node, targets, objective_name,
            )

        if "monitor-logs" in actions:
            return self._execute_monitor_objective(targets)

        logger.warning("docker: no handler for actions %s", actions)
        return False

    def _execute_read_file_objective(
        self,
        agent_cid: str,
        agent_node: str,
        targets: list[str],
        objective_name: str,
    ) -> bool:
        client = self._get_client()
        content_section = self._scenario.get("content", {})

        for target_name in targets:
            content_spec = content_section.get(target_name, {})
            target_node = content_spec.get("target", "")
            file_path = content_spec.get("path", "")

            if not target_node or not file_path:
                continue

            if target_node == agent_node:
                result = _exec_run(client, agent_cid, ["cat", file_path])
            else:
                target_account = self._find_account_on_node(target_node)
                if not target_account:
                    logger.warning("docker: no account to SSH to %s", target_node)
                    return False

                username = target_account["username"]
                result = _exec_run(
                    client, agent_cid,
                    ["ssh",
                     "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null",
                     "-o", "LogLevel=ERROR",
                     "-i", "/root/.ssh/id_ed25519",
                     f"{username}@{target_node}",
                     "cat", file_path],
                )

                if result.exit_code != 0:
                    result = self._ssh_via_hop(
                        agent_cid, username, target_node, f"cat {file_path}",
                    )

            output = result.output.strip() if result.output else ""
            if result.exit_code == 0 and output:
                self.captured_flags[objective_name] = output
                logger.info("docker: objective %s captured: %s", objective_name, output[:40])
                return True
            else:
                logger.warning(
                    "docker: objective %s failed (rc=%d): %s",
                    objective_name, result.exit_code, result.output.strip() if result.output else "",
                )

        return False

    def _execute_monitor_objective(self, targets: list[str]) -> bool:
        return True

    def _ssh_via_hop(
        self,
        agent_cid: str,
        username: str,
        target_node: str,
        command: str,
    ) -> ExecResult:
        if not self._provisioner or not self._scenario:
            return ExecResult(exit_code=1, output="no provisioner")

        client = self._get_client()
        infra = self._scenario.get("infrastructure", {})
        target_links = set(infra.get(target_node, {}).get("links", []))

        for node_name in infra:
            node_links = set(infra[node_name].get("links", []))
            if not target_links & node_links:
                continue
            if node_name == target_node:
                continue

            hop_account = self._find_account_on_node(node_name)
            if not hop_account:
                continue
            hop_user = hop_account["username"]

            result = _exec_run(
                client, agent_cid,
                ["ssh",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "LogLevel=ERROR",
                 "-i", "/root/.ssh/id_ed25519",
                 f"{hop_user}@{node_name}",
                 f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                 f" -o LogLevel=ERROR"
                 f" -i /home/{hop_user}/.ssh/id_ed25519"
                 f" {username}@{target_node} {command}"],
            )
            if result.exit_code == 0:
                return result

        return ExecResult(exit_code=1, output="no reachable hop")

    def _find_account_on_node(self, node_name: str) -> dict[str, Any] | None:
        if not self._scenario:
            return None
        for _name, acct in self._scenario.get("accounts", {}).items():
            if acct.get("node") == node_name:
                return acct
        return None

    def _check_condition_by_address(self, condition_address: str) -> bool:
        if not self._provisioner or not self._scenario:
            return False

        parts = condition_address.split(".")
        if len(parts) < 4:
            return False
        node_name = parts[2]
        condition_name = ".".join(parts[3:])

        conditions = self._scenario.get("conditions", {})
        cond_spec = conditions.get(condition_name, {})
        command = cond_spec.get("command", "")
        if not command:
            return False

        cid = self._provisioner.container_for_node(node_name)
        if not cid:
            return False

        try:
            client = self._get_client()
            result = _exec_run(client, cid, command)
            return result.exit_code == 0
        except Exception:
            return False


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

    def _get_client(self) -> Any:
        return self._provisioner._get_client()

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
        node_address = op.payload.get("node_address", "")

        template = spec.get("template", {})
        command = template.get("command") or spec.get("command")

        if not command or not node_address:
            return True

        cid = self._provisioner.containers.get(node_address)
        if not cid:
            return False

        try:
            client = self._get_client()
            result = _exec_run(client, cid, command)
            return result.exit_code == 0
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
    """Factory for Docker runtime components.

    Pass ``scenario=<parsed SDL dict>`` to enable real workflow execution
    (SSH between containers, file reads, condition checks).  Without a
    scenario the orchestrator falls back to bookkeeping-only mode.
    """
    prefix = config.get("project_prefix", "aptl")
    scenario = config.get("scenario")
    use_ssh_image = config.get("use_ssh_image", bool(scenario))
    provisioner = DockerProvisioner(
        project_prefix=prefix, use_ssh_image=use_ssh_image,
    )
    orchestrator = DockerOrchestrator(provisioner=provisioner, scenario=scenario)
    evaluator = DockerEvaluator(provisioner)
    return RuntimeTargetComponents(
        provisioner=provisioner,
        orchestrator=orchestrator,
        evaluator=evaluator,
    )


def create_docker_target(**config: Any) -> RuntimeTarget:
    """Convenience helper returning the fully configured Docker target.

    Pass ``scenario=<parsed SDL dict>`` in *config* to enable eager
    workflow execution in the orchestrator.
    """
    manifest = create_docker_manifest(**config)
    components = create_docker_components(manifest=manifest, **config)
    return RuntimeTarget(
        name="docker",
        manifest=manifest,
        provisioner=components.provisioner,
        orchestrator=components.orchestrator,
        evaluator=components.evaluator,
    )
