"""Make declared operator interactive access reachable from the operator's host.

A scenario declares that an operator reaches a node interactively
(``agents.red-team-operator.interactive_access.kali-ssh``). TechVault's target
nodes sit on internal networks, and Docker never routes host traffic onto an
internal network, so a published port on the node itself is unreachable. The
scenario says *what*; under open realization the backend chooses *how*, and it
must either make the access true or refuse the scenario — never leave a
declared access silently unreachable (issue #1006).

The how is one loopback-published byte relay per declared access, attached to
the target's own network and to a non-internal access network. The relay
carries no credentials and handles no protocol, so the target's SSH daemon —
for Kali, the session-capture broker — keeps authentication and custody.

Each endpoint is proven, not assumed: after start the backend connects to the
published host port and requires an SSH identification banner from the far
side. A relay that starts but reaches nothing fails the realization.
"""

from __future__ import annotations

import os
import re
import socket
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aptl.core.deployment._compose_resource_ownership import (
    OwnershipConflictError,
    ResourceReceipt,
)
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.realization import DeploymentOperatorAccess

log = get_logger("deployment.operator_access")

OPERATOR_ACCESS_IMAGE = "aptl/operator-access-proxy:latest"
OPERATOR_ACCESS_NETWORK_SUFFIX = "aptl-operator-access"
OPERATOR_ACCESS_APPARATUS_ID = "aptl.apparatus.operator-interactive-access"
SSH_CHANNEL = "ssh"
_SSH_TARGET_PORT = 22
_LOOPBACK = "127.0.0.1"
_BANNER_PREFIX = b"SSH-2.0-"
# The relay is up within seconds, but the far side is an sshd that may still be
# settling behind the capture broker when the relay first answers. Bounded,
# generous relative to the observed few-second settle.
_READY_TIMEOUT_SECONDS = 120
_READY_INTERVAL_SECONDS = 2
_BANNER_READ_TIMEOUT_SECONDS = 5
_PUBLIC_KEY_RE = re.compile(
    r"(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+( [^\n]*)?"
)
# Positional args: $1 user, $2 public key. The user must already exist as a
# declared identity; the script never creates one.
_AUTHORIZE_SCRIPT = (
    'set -eu; home=$(getent passwd "$1" | cut -d: -f6); '
    'test -n "$home"; '
    'install -d -m 0700 -o "$1" -g "$(id -gn "$1")" "$home/.ssh"; '
    'keys="$home/.ssh/authorized_keys"; touch "$keys"; '
    'grep -qxF -- "$2" "$keys" || printf "%s\\n" "$2" >> "$keys"; '
    'chown "$1":"$(id -gn "$1")" "$keys"; chmod 0600 "$keys"'
)


@dataclass(frozen=True)
class OperatorAccessEndpoint(object):
    """The backend's apparatus for one declarable interactive-access target.

    ``env_var`` / ``default_port`` are the host publication, resolved through
    the same remap path as every other published APTL port, so a lab whose
    default port is taken still reaches its target and host-run MCP clients are
    pointed at the resolved port.
    """

    target_node: str
    target_container: str
    relay_container: str
    listen_port: int
    env_var: str
    default_port: int
    profile: str
    # The declared local identity the operator logs in as, when the scenario
    # declares the access but provisions no key for it. The backend installs the
    # operator's public key for exactly that identity. None when the scenario
    # already delivers the authorized key (Kali's arrives with its SSH bundle).
    authorized_user: str | None = None


# The backend's apparatus catalog: which declared targets it can make reachable,
# and where. A declared access to a target absent here is refused at admission
# rather than realized as an unreachable node. `APTL_HP_KALI_SSH_PROXY_2023` keeps
# the name host-run MCP clients (mcp-red) already resolve.
OPERATOR_ACCESS_ENDPOINTS: dict[str, OperatorAccessEndpoint] = {
    "kali": OperatorAccessEndpoint(
        target_node="kali",
        target_container="aptl-kali",
        relay_container="aptl-operator-ssh-kali",
        listen_port=2023,
        env_var="APTL_HP_KALI_SSH_PROXY_2023",
        default_port=2023,
        profile="kali",
    ),
    "soc-workstation": OperatorAccessEndpoint(
        target_node="soc-workstation",
        target_container="aptl-soc-workstation",
        relay_container="aptl-operator-ssh-soc-workstation",
        listen_port=2024,
        env_var="APTL_HP_SOC_WORKSTATION_SSH_2024",
        default_port=2024,
        profile="soc",
        authorized_user="analyst",
    ),
}


def realizable_access(target_node: str, channel: str) -> bool:
    """Return whether the backend has apparatus for this declared access."""

    return channel == SSH_CHANNEL and target_node in OPERATOR_ACCESS_ENDPOINTS


def resolved_host_port(endpoint: OperatorAccessEndpoint) -> int:
    """Return the host port the lab's port resolution selected for an endpoint."""

    raw = os.environ.get(endpoint.env_var, "")
    return int(raw) if raw.isdigit() else endpoint.default_port


class ComposeOperatorAccessMixin(object):
    """Start and prove one loopback relay per declared operator access.

    Relays and their access network are backend resources like any other: they
    carry workspace-scoped names and ownership labels and are recorded as
    receipts, so teardown removes them and concurrent labs cannot collide.
    """

    def activate_operator_access(
        self,
        accesses: Sequence["DeploymentOperatorAccess"],
        *,
        operator_public_key: str | None = None,
    ) -> list[str]:
        """Make every admitted operator access reachable, or report why not.

        Runs after the capture apparatus is active: Kali's own sshd is moved
        behind the session-capture broker during realization, and the broker
        only serves once lab start activates it for the run. Proving Kali's
        access any earlier finds nothing listening on port 22.
        """

        accesses = tuple(accesses)
        if not accesses:
            return []
        try:
            self._ensure_resource_ownership()
            self._ownership_daemon_id()
        except OwnershipConflictError:
            return ["operator access: backend resource ownership is unavailable"]
        failures = self.ensure_generic_base_image(OPERATOR_ACCESS_IMAGE)
        network: str | None = None
        if not failures:
            network, failures = self._ensure_operator_access_network()
        for access in accesses if network is not None and not failures else ():
            failures.extend(
                self._authorize_operator(access, operator_public_key)
                or self._start_operator_relay(access, network)
            )
        if failures:
            return failures
        failures = _prove_endpoints(
            OPERATOR_ACCESS_ENDPOINTS[access.target_node] for access in accesses
        )
        if not failures:
            for access in accesses:
                endpoint = OPERATOR_ACCESS_ENDPOINTS[access.target_node]
                log.info(
                    "Operator access %s (%s to %s) published on 127.0.0.1:%d",
                    access.access_id,
                    access.channel,
                    access.target_node,
                    resolved_host_port(endpoint),
                )
        return failures

    def _authorize_operator(
        self, access: "DeploymentOperatorAccess", operator_public_key: str | None
    ) -> list[str]:
        """Install the operator's public key for the declared login identity.

        A declared access with no delivered credential is not usable access.
        The key is public material, passed as a discrete argument to a fixed
        script — never interpolated into shell syntax.
        """

        endpoint = OPERATOR_ACCESS_ENDPOINTS[access.target_node]
        user = endpoint.authorized_user
        if user is None:
            return []
        key = (operator_public_key or "").strip()
        if not _PUBLIC_KEY_RE.fullmatch(key):
            return [
                f"operator access {access.access_id}: no valid operator public key "
                f"to authorize {user} on {endpoint.target_node}"
            ]
        try:
            installed = self.container_exec(
                endpoint.target_container,
                ["sh", "-c", _AUTHORIZE_SCRIPT, "aptl-authorize-operator", user, key],
                timeout=60,
            )
        except (BackendTimeoutError, OwnershipConflictError, OSError):
            installed = None
        if installed is None or installed.returncode != 0:
            return [
                f"operator access {access.access_id}: could not authorize "
                f"{user} on {endpoint.target_node}"
            ]
        return []

    def _ensure_operator_access_network(self) -> tuple[str | None, list[str]]:
        """Reuse or create the receipt-owned, non-internal access network."""

        external = f"{self._project_name}_{OPERATOR_ACCESS_NETWORK_SUFFIX}"
        try:
            self._resolve_owned_network_id(OPERATOR_ACCESS_NETWORK_SUFFIX)
            return external, []
        except OwnershipConflictError:
            pass
        ownership = self._ensure_resource_ownership()
        attempt_id = self._resource_attempt_id
        command = [
            "docker",
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            f"com.docker.compose.project={self._project_name}",
            "--label",
            f"aptl.apparatus={OPERATOR_ACCESS_APPARATUS_ID}",
        ]
        for label, value in ownership.labels(attempt_id=attempt_id).items():
            command.extend(("--label", f"{label}={value}"))
        command.append(external)
        created = self._run(command, timeout=60)
        native_id = str(created.stdout or "").strip()
        if created.returncode != 0 or not native_id:
            return None, [f"could not create the operator access network {external}"]
        try:
            ownership.record(
                ResourceReceipt(
                    kind="network",
                    native_id=native_id,
                    external_name=external,
                    semantic_name=OPERATOR_ACCESS_NETWORK_SUFFIX,
                    node_address=OPERATOR_ACCESS_NETWORK_SUFFIX,
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=self._ownership_daemon_id(),
                    attempt_id=attempt_id,
                    managed_by="direct",
                )
            )
        except OwnershipConflictError:
            self._run(["docker", "network", "rm", native_id], timeout=60)
            return None, ["could not record ownership of the operator access network"]
        return external, []

    def _start_operator_relay(
        self, access: "DeploymentOperatorAccess", network: str
    ) -> list[str]:
        """Start one receipt-owned relay and join it to its target's network."""

        endpoint = OPERATOR_ACCESS_ENDPOINTS[access.target_node]
        target = self._target_identity(endpoint.target_container)
        if target is None:
            return [
                f"operator access {access.access_id}: target "
                f"{endpoint.target_node} is not running on a network"
            ]
        target_name, target_network = target
        self._remove_existing_relay(endpoint.relay_container)
        ownership = self._ensure_resource_ownership()
        attempt_id = self._resource_attempt_id
        external = ownership.container_name(endpoint.relay_container)
        started = self._run(
            _relay_run_command(
                endpoint,
                access,
                external_name=external,
                labels={
                    "com.docker.compose.project": self._project_name,
                    **ownership.labels(attempt_id=attempt_id),
                },
                network=network,
                target_host=target_name,
                host_port=resolved_host_port(endpoint),
            ),
            timeout=120,
        )
        native_id = str(started.stdout or "").strip()
        if started.returncode != 0 or not native_id:
            return [f"operator access {access.access_id}: relay did not start"]
        try:
            ownership.record(
                ResourceReceipt(
                    kind="container",
                    native_id=native_id,
                    external_name=external,
                    semantic_name=endpoint.relay_container,
                    node_address=f"operator-access.{access.access_id}",
                    workspace_id=ownership.workspace_id,
                    project_name=ownership.project_name,
                    daemon_id=self._ownership_daemon_id(),
                    attempt_id=attempt_id,
                    managed_by="direct",
                )
            )
        except OwnershipConflictError:
            self._run(["docker", "rm", "-f", native_id], timeout=60)
            return [f"operator access {access.access_id}: relay ownership not recorded"]
        joined = self._run(
            ["docker", "network", "connect", target_network, native_id],
            timeout=60,
        )
        if joined.returncode != 0:
            return [
                f"operator access {access.access_id}: relay could not join "
                f"{endpoint.target_node}'s network"
            ]
        return []

    def _remove_existing_relay(self, semantic_name: str) -> None:
        """Remove a still-running relay this workspace owns, if there is one."""

        try:
            native_id = self._resolve_owned_container_id(semantic_name)
        except OwnershipConflictError:
            return
        self._run(["docker", "rm", "-f", native_id], timeout=60)

    def _target_identity(self, semantic_name: str) -> tuple[str, str] | None:
        """Return the running target's external name and first network."""

        try:
            inspected = self.container_inspect(semantic_name)
        except (BackendTimeoutError, OwnershipConflictError, OSError, ValueError):
            return None
        name = str(inspected.get("Name", "")).removeprefix("/") if inspected else ""
        settings = inspected.get("NetworkSettings") if inspected else None
        networks = settings.get("Networks") if isinstance(settings, dict) else None
        if not name or not isinstance(networks, dict) or not networks:
            return None
        return name, sorted(networks)[0]


def _relay_run_command(
    endpoint: OperatorAccessEndpoint,
    access: "DeploymentOperatorAccess",
    *,
    external_name: str,
    labels: dict[str, str],
    network: str,
    target_host: str,
    host_port: int,
) -> list[str]:
    """Build the least-privileged run command for one relay."""

    command = ["docker", "run", "-d", "--name", external_name]
    for label, value in {
        **labels,
        "aptl.apparatus": OPERATOR_ACCESS_APPARATUS_ID,
        "aptl.operator-access.id": access.access_id,
    }.items():
        command.extend(("--label", f"{label}={value}"))
    command.extend(
        [
            "--restart",
            "unless-stopped",
            "--network",
            network,
            # Loopback only: declared access is for the operator on this host,
            # not for anything else on the host's networks.
            "-p",
            f"{_LOOPBACK}:{host_port}:{endpoint.listen_port}",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "64m",
            "-e",
            f"APTL_PROXY_LISTEN_PORT={endpoint.listen_port}",
            "-e",
            f"APTL_PROXY_TARGET_HOST={target_host}",
            "-e",
            f"APTL_PROXY_TARGET_PORT={_SSH_TARGET_PORT}",
            OPERATOR_ACCESS_IMAGE,
        ]
    )
    return command


def _prove_endpoints(
    endpoints: Iterable[OperatorAccessEndpoint],
    *,
    timeout: float | None = None,
    interval: float | None = None,
) -> list[str]:
    """Require an SSH identification banner through every published endpoint."""

    timeout = _READY_TIMEOUT_SECONDS if timeout is None else timeout
    interval = _READY_INTERVAL_SECONDS if interval is None else interval

    pending = {endpoint.relay_container: endpoint for endpoint in endpoints}
    deadline = time.monotonic() + timeout
    while pending:
        for name, endpoint in list(pending.items()):
            if ssh_banner_reachable(_LOOPBACK, resolved_host_port(endpoint)):
                del pending[name]
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(interval)
    return [
        f"operator access through {endpoint.relay_container} "
        f"(127.0.0.1:{resolved_host_port(endpoint)}) did not reach an SSH server "
        f"within {int(timeout)}s"
        for endpoint in pending.values()
    ]


def ssh_banner_reachable(host: str, port: int) -> bool:
    """Return whether an SSH server identifies itself at host:port."""

    try:
        with socket.create_connection(
            (host, port), timeout=_BANNER_READ_TIMEOUT_SECONDS
        ) as conn:
            conn.settimeout(_BANNER_READ_TIMEOUT_SECONDS)
            return conn.recv(len(_BANNER_PREFIX)).startswith(_BANNER_PREFIX)
    except OSError:
        return False


def operator_access_details(
    accesses: Sequence["DeploymentOperatorAccess"],
) -> list[dict[str, object]]:
    """Report each admitted access and the endpoint planned for it.

    Apply details are written before lab start publishes and proves the relays,
    so this says what was admitted and where it will be published — not that it
    is reachable. Reachability is proven by `activate_operator_access`, and a
    failure there fails the start.
    """

    details: list[dict[str, object]] = []
    for access in accesses:
        endpoint = OPERATOR_ACCESS_ENDPOINTS.get(access.target_node)
        if endpoint is None:
            continue
        details.append(
            {
                **access.details(),
                "state": "admitted",
                "apparatus_id": OPERATOR_ACCESS_APPARATUS_ID,
                "relay_container": endpoint.relay_container,
                "planned_host_ip": _LOOPBACK,
                "planned_host_port": resolved_host_port(endpoint),
                "environment_visible": True,
            }
        )
    return details
