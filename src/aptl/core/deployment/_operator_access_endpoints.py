"""Which declared interactive accesses this backend has apparatus for.

A scenario declares that an operator reaches a node interactively; this is the
catalog of what the backend can actually make reachable, and where. A declared
access to a target absent here is refused at admission rather than realized as
an unreachable node.

The relay's host publication goes through the same remap path as every other
published APTL port, so a lab whose default port is taken still reaches its
target and host-run MCP clients are pointed at the resolved port.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

OPERATOR_ACCESS_IMAGE = "aptl/operator-access-proxy:latest"
SSH_CHANNEL = "ssh"
_SSH_TARGET_PORT = 22


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
    # The identity the operator actually logs in as. Realization is proven by
    # authenticating as this user, not merely by reaching an SSH server
    # (issue #1105).
    login_user: str = ""
    # The declared local identity whose authorized_keys the backend installs,
    # when the scenario declares the access but provisions no key for it. None
    # when the scenario already delivers the authorized key (Kali's arrives with
    # its SSH bundle).
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
        login_user="kali",
    ),
    "soc-workstation": OperatorAccessEndpoint(
        target_node="soc-workstation",
        target_container="aptl-soc-workstation",
        relay_container="aptl-operator-ssh-soc-workstation",
        listen_port=2024,
        env_var="APTL_HP_SOC_WORKSTATION_SSH_2024",
        default_port=2024,
        profile="soc",
        login_user="analyst",
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
