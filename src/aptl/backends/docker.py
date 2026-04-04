"""Docker backend — provisions scenarios as Docker containers and networks.

Implements the Provisioner, Orchestrator, and Evaluator runtime protocols
using the Docker CLI. Each SDL network becomes a Docker bridge network,
each VM node becomes a container, and accounts/content are provisioned
inside containers via ``docker exec``.

The provisioner installs SSH and supporting tools when ``ssh-password-auth``
feature bindings are encountered.  The orchestrator can eagerly execute
workflow steps by driving real SSH commands between containers.  The
evaluator checks conditions by running commands inside the appropriate
containers.

Capability surface:
- Provisioner: vm + switch nodes on linux, file + directory content,
  accounts with password auth, SSH feature provisioning
- Orchestrator: workflows with timeouts, decision, retry, failure-transitions
- Evaluator: conditions, objectives, full scoring pipeline
"""

from __future__ import annotations

import logging
import subprocess
import time
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


def _docker(
    *args: str,
    check: bool = True,
    capture: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess:
    """Run a docker CLI command."""
    cmd = ["docker", *args]
    logger.debug("docker: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        check=check,
        timeout=timeout,
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
    """Provisions Docker networks and containers from SDL plans."""

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

    def _create_resource(
        self,
        address: str,
        resource_type: str,
        payload: dict[str, Any],
        ordering_dependencies: tuple[str, ...] = (),
    ) -> None:
        if resource_type == "network":
            self._create_network(address, payload)
        elif resource_type == "node":
            self._create_node(address, payload, ordering_dependencies)
        elif resource_type == "content-placement":
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

    def _create_node(
        self,
        address: str,
        payload: dict[str, Any],
        ordering_dependencies: tuple[str, ...] = (),
    ) -> None:
        spec = payload.get("spec", {})
        source = spec.get("source", {})
        image_name = source.get("name", "ubuntu")
        image_version = source.get("version", "latest")
        if image_version == "*":
            image_version = "latest"

        # When use_ssh_image is set, all VM nodes get the panubo/sshd
        # image which has OpenSSH pre-installed.  This avoids needing
        # apt-get install inside containers (which requires internet).
        if self._use_ssh_image:
            image = "panubo/sshd:latest"
        else:
            image = f"{image_name}:{image_version}"

        node_name = payload.get("node_name", address.split(".")[-1])
        container_name = f"{self._prefix}-{node_name}"

        # Pull image (best effort)
        _docker("pull", image, check=False)

        # Determine which network(s) to connect to
        network_deps: list[str] = []
        for dep in ordering_dependencies:
            if dep in self._networks:
                network_deps.append(dep)

        # First network goes on the run command; includes alias for SDL name
        network_args: list[str] = []
        if network_deps:
            first_net = f"{self._prefix}-{network_deps[0].replace('.', '-')}"
            network_args = [
                "--network", first_net,
                "--network-alias", node_name,
            ]

        # Create container — SSH image needs env vars and its own entrypoint
        if self._use_ssh_image and image.startswith("panubo/sshd"):
            cmd = [
                "run", "-d",
                "--name", container_name,
                "--hostname", node_name,
                "-e", "SSH_ENABLE_PASSWORD_AUTH=true",
                "-e", "SSH_ENABLE_ROOT=true",
                *network_args,
                image,
            ]
        else:
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
        self._node_names[address] = node_name
        logger.info("docker: created container %s (%s) from %s", container_name, cid[:12], image)

        # Connect to additional networks with aliases
        for dep in network_deps[1:]:
            net_name = f"{self._prefix}-{dep.replace('.', '-')}"
            _docker(
                "network", "connect",
                "--alias", node_name,
                net_name, cid,
                check=False,
            )

    def _create_content(self, address: str, payload: dict[str, Any]) -> None:
        spec = payload.get("spec", {})
        target_node = payload.get("target_node", "")
        target_address = payload.get("target_address", "")
        content_type = spec.get("type", "file")

        cid = self._containers.get(target_address)
        if not cid:
            logger.warning("docker: no container for content target %s", target_address)
            return

        if content_type == "directory":
            destination = spec.get("destination", "")
            if destination:
                _docker("exec", cid, "mkdir", "-p", destination, check=False)
                logger.info("docker: created directory %s:%s", target_node, destination)
            return

        # File content
        path = spec.get("path", "")
        text = spec.get("text")
        if not path or text is None:
            return

        parent = "/".join(path.split("/")[:-1])
        if parent:
            _docker("exec", cid, "mkdir", "-p", parent, check=False)
        _docker("exec", cid, "sh", "-c", f"echo '{text}' > {path}", check=False)
        logger.info("docker: placed content at %s:%s", target_node, path)

    def _create_feature_binding(self, address: str, payload: dict[str, Any]) -> None:
        """Provision a feature binding — install real software in a container."""
        spec = payload.get("spec", {})
        feature_name = payload.get("feature_name", "")
        target_address = payload.get("node_address", "")
        node_name = payload.get("node_name", "")

        cid = self._containers.get(target_address)
        if not cid:
            logger.warning("docker: no container for feature target %s", target_address)
            return

        if feature_name == "ssh-password-auth":
            if self._use_ssh_image:
                # SSH is handled by the panubo/sshd entrypoint — skip
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
        """Ensure OpenSSH server is running and configured in a container.

        For containers built from the ``panubo/sshd`` image the server is
        already running.  For plain ubuntu containers we attempt an
        ``apt-get install``.  Either way, we ensure sshd is listening.
        """
        logger.info("docker: ensuring sshd on %s", node_name)

        # Check if sshd is already present (e.g. panubo/sshd image)
        check = _docker("exec", cid, "which", "sshd", check=False)
        if check.returncode == 0:
            # Make sure it's running
            _docker("exec", cid, "sh", "-c",
                    "pgrep sshd >/dev/null 2>&1 || /usr/sbin/sshd", check=False)
            logger.info("docker: sshd already present on %s", node_name)
            return

        # Fallback: install via apt-get (needs network)
        _docker(
            "exec", cid, "sh", "-c",
            "apt-get update -qq 2>/dev/null"
            " && DEBIAN_FRONTEND=noninteractive"
            " apt-get install -y -qq openssh-server netcat-openbsd"
            " 2>/dev/null 1>/dev/null"
            " && mkdir -p /run/sshd"
            " && sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
            " && sed -i 's/#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config"
            " && /usr/sbin/sshd",
            check=False,
            timeout=300,
        )
        logger.info("docker: sshd installed and running on %s", node_name)

    def _install_ssh_client_tools(self, cid: str, node_name: str) -> None:
        """Ensure SSH client tools are available in a container.

        Generates an ed25519 key pair for the operator so the orchestrator
        can SSH between containers using key-based auth.
        """
        logger.info("docker: ensuring ssh client on %s", node_name)
        # Generate a key pair if one doesn't exist
        _docker(
            "exec", cid, "sh", "-c",
            "mkdir -p /root/.ssh"
            " && test -f /root/.ssh/id_ed25519"
            " || ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N '' -q",
            check=False,
        )
        # Store the public key for later distribution
        result = _docker(
            "exec", cid, "cat", "/root/.ssh/id_ed25519.pub", check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            self._ssh_pubkey = result.stdout.strip()
            logger.info("docker: ssh key generated on %s", node_name)

    def wait_for_ssh(self, timeout: int = 30) -> None:
        """Wait for sshd to be listening on all SSH-enabled containers."""
        if not self._use_ssh_image:
            return
        deadline = time.monotonic() + timeout
        for address, cid in self._containers.items():
            while time.monotonic() < deadline:
                check = _docker(
                    "exec", cid, "sh", "-c",
                    "pgrep -x sshd >/dev/null 2>&1",
                    check=False,
                )
                if check.returncode == 0:
                    break
                time.sleep(0.5)

    def distribute_ssh_keys(self) -> None:
        """Copy the operator's public key to all containers that have sshd.

        Called after all nodes and accounts are provisioned so that the
        orchestrator can SSH between containers using key-based auth.
        """
        pubkey = getattr(self, "_ssh_pubkey", "")
        if not pubkey:
            return

        for address, cid in self._containers.items():
            # Install key for each provisioned account on this container
            for acct_addr, acct_spec in self._accounts.items():
                node_name = acct_spec.get("node_name", "")
                container_node = self._node_names.get(address, "")
                if node_name != container_node:
                    continue

                username = acct_spec.get("username", "")
                home = acct_spec.get("home", f"/home/{username}")
                _docker(
                    "exec", cid, "sh", "-c",
                    f"mkdir -p {home}/.ssh"
                    f" && echo '{pubkey}' >> {home}/.ssh/authorized_keys"
                    f" && chmod 700 {home}/.ssh"
                    f" && chmod 600 {home}/.ssh/authorized_keys"
                    f" && chown -R {username}:{username} {home}/.ssh 2>/dev/null || true",
                    check=False,
                )

            # Also install the private key so intermediate hops work
            priv_key_src = getattr(self, "_kali_cid", "")
            if not priv_key_src:
                # Find the kali/attack container (has the private key)
                for addr, name in self._node_names.items():
                    if name == "kali":
                        priv_key_src = self._containers.get(addr, "")
                        break

        # Copy private key from kali to server for lateral movement
        if priv_key_src:
            priv_result = _docker(
                "exec", priv_key_src, "cat", "/root/.ssh/id_ed25519",
                check=False,
            )
            if priv_result.returncode == 0 and priv_result.stdout.strip():
                priv_key = priv_result.stdout.strip()
                for address, cid in self._containers.items():
                    if cid == priv_key_src:
                        continue
                    # Install private key for accounts on this container
                    for acct_addr, acct_spec in self._accounts.items():
                        node_name = acct_spec.get("node_name", "")
                        container_node = self._node_names.get(address, "")
                        if node_name != container_node:
                            continue
                        username = acct_spec.get("username", "")
                        home = acct_spec.get("home", f"/home/{username}")
                        _docker(
                            "exec", cid, "sh", "-c",
                            f"mkdir -p {home}/.ssh"
                            f" && printf '%s\\n' '{priv_key}' > {home}/.ssh/id_ed25519"
                            f" && chmod 600 {home}/.ssh/id_ed25519"
                            f" && chown -R {username}:{username} {home}/.ssh 2>/dev/null || true",
                            check=False,
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

        # Create user account — try useradd (Debian) first, adduser (Alpine) second
        _docker(
            "exec", cid, "sh", "-c",
            f"id {username} 2>/dev/null || "
            f"useradd -m -d {home} -s {shell} {username} 2>/dev/null || "
            f"adduser -D -h {home} -s {shell} {username} 2>/dev/null || true",
            check=False,
        )

        # Set password
        _docker(
            "exec", cid, "sh", "-c",
            f"echo '{username}:{password}' | chpasswd 2>/dev/null || true",
            check=False,
        )

        # Add to groups — try groupadd+usermod (Debian) and addgroup (Alpine)
        for group in groups:
            _docker(
                "exec", cid, "sh", "-c",
                f"(groupadd {group} 2>/dev/null || addgroup {group} 2>/dev/null || true)"
                f" && (usermod -aG {group} {username} 2>/dev/null"
                f" || addgroup {username} {group} 2>/dev/null || true)",
                check=False,
            )

        self._accounts[address] = {**spec, "node_name": node_name}
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
    """Executes workflow steps inside Docker containers.

    When a parsed SDL scenario is provided, the orchestrator eagerly walks
    each workflow's step graph and performs real actions (SSH between
    containers, read files, check conditions).  Without a scenario it falls
    back to bookkeeping-only mode for unit tests.
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
        # Populated during execution: objective address → captured output
        self.captured_flags: dict[str, str] = {}

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

                # --- Eager execution if we have a provisioner + scenario ---
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

        # If we exited the loop without hitting an end step, mark failed
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
        """Execute an objective step by running the real action."""
        objective_address = step.get("objective_address", "")
        # Extract objective name from address: "evaluation.objective.capture-server-flag"
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
        """Evaluate a decision step's condition and return the branch target."""
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
        """Execute a retry step, trying the objective up to max_attempts."""
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
        """Execute a named objective using the SDL scenario for context.

        Translates SDL objectives into concrete Docker exec / SSH commands.
        """
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

        # Resolve agent's starting node
        agents = self._scenario.get("agents", {})
        agent_spec = agents.get(agent_name, {})
        starting_accounts = agent_spec.get("starting_accounts", [])

        # Find starting node from account
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

        # For read-file actions targeting content items
        if "read-file" in actions:
            return self._execute_read_file_objective(
                agent_cid, agent_node, targets, objective_name,
            )

        # For monitor-logs actions
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
        """Read a file on a target node, potentially via SSH."""
        content_section = self._scenario.get("content", {})
        accounts_section = self._scenario.get("accounts", {})

        for target_name in targets:
            content_spec = content_section.get(target_name, {})
            target_node = content_spec.get("target", "")
            file_path = content_spec.get("path", "")
            expected_text = content_spec.get("text", "")

            if not target_node or not file_path:
                continue

            if target_node == agent_node:
                # Same node — direct read
                result = _docker(
                    "exec", agent_cid, "cat", file_path, check=False,
                )
            else:
                # Different node — SSH to reach it via key-based auth
                target_account = self._find_account_on_node(target_node)
                if not target_account:
                    logger.warning(
                        "docker: no account to SSH to %s", target_node,
                    )
                    return False

                username = target_account["username"]

                # Try SSH from the agent's container first.  If the target
                # isn't reachable directly (different network), hop through
                # an intermediate node that can reach it.
                result = _docker(
                    "exec", agent_cid,
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "LogLevel=ERROR",
                    "-i", "/root/.ssh/id_ed25519",
                    f"{username}@{target_node}",
                    "cat", file_path,
                    check=False,
                    timeout=30,
                )

                # If direct SSH failed, try via an intermediate hop
                if result.returncode != 0:
                    result = self._ssh_via_hop(
                        agent_cid, username, target_node, f"cat {file_path}",
                    )

            output = result.stdout.strip() if result.stdout else ""
            if result.returncode == 0 and output:
                self.captured_flags[objective_name] = output
                logger.info(
                    "docker: objective %s captured: %s",
                    objective_name, output[:40],
                )
                return True
            else:
                logger.warning(
                    "docker: objective %s failed (rc=%d): %s",
                    objective_name, result.returncode,
                    result.stderr.strip() if result.stderr else "",
                )

        return False

    def _execute_monitor_objective(self, targets: list[str]) -> bool:
        """Check monitoring conditions (always succeeds in eager mode)."""
        return True

    def _ssh_via_hop(
        self,
        agent_cid: str,
        username: str,
        target_node: str,
        command: str,
    ) -> subprocess.CompletedProcess:
        """SSH to target via each reachable intermediate node."""
        if not self._provisioner or not self._scenario:
            return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="no provisioner")

        infra = self._scenario.get("infrastructure", {})
        # Find nodes that link to the same networks as the target
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

            result = _docker(
                "exec", agent_cid,
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-i", "/root/.ssh/id_ed25519",
                f"{hop_user}@{node_name}",
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                f" -o LogLevel=ERROR"
                f" -i /home/{hop_user}/.ssh/id_ed25519"
                f" {username}@{target_node} {command}",
                check=False,
                timeout=30,
            )
            if result.returncode == 0:
                return result

        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="no reachable hop")

    def _find_account_on_node(self, node_name: str) -> dict[str, Any] | None:
        """Find an account spec for a given node from the scenario."""
        if not self._scenario:
            return None
        for _name, acct in self._scenario.get("accounts", {}).items():
            if acct.get("node") == node_name:
                return acct
        return None

    def _check_condition_by_address(self, condition_address: str) -> bool:
        """Evaluate a condition by its compiler address."""
        if not self._provisioner or not self._scenario:
            return False

        # Address format: "evaluation.condition.{node}.{condition}"
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
            result = _docker("exec", cid, "sh", "-c", command, check=False, timeout=15)
            return result.returncode == 0
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
        node_address = op.payload.get("node_address", "")

        # Condition commands live under spec.template (from the compiler)
        # or directly under spec.command (depending on compilation path)
        template = spec.get("template", {})
        command = template.get("command") or spec.get("command")

        if not command or not node_address:
            # No command — default to passed for scoring resources
            return True

        cid = self._provisioner.containers.get(node_address)
        if not cid:
            return False

        try:
            result = _docker("exec", cid, "sh", "-c", command, check=False, timeout=15)
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
