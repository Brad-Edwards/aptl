"""Derive native Kali MCP ingress and capture targets from the Docker runtime."""

from ipaddress import ip_address
from pathlib import Path
from typing import Any

from aptl.core.deployment._compose_capture_config import KALI_CAPTURE_CONTAINER
from aptl.core.deployment._compose_resource_ownership import WorkspaceOwnership

# A new variable, so ADR-062 names it for LilRAE. It cannot join the
# ``APTL_HP_*`` injection contract, which carries only decimal host ports.
CAPTURE_CONTAINER_VARIABLE = "LILRAE_MCP_CAPTURE_CONTAINER"


def kali_capture_container(
    project_dir: Path, logical_project_name: str
) -> dict[str, str]:
    """Name the workspace-scoped capture sidecar that the red MCP harvests.

    Since #1054 the backend creates ``aptl-kali-capture`` under the name that
    ``WorkspaceOwnership.container_name`` returns, and receipt capture refuses
    any other name. The fixed name in the MCP configuration never matches.
    """
    ownership = WorkspaceOwnership.load(project_dir, logical_project_name)
    if ownership is None:
        raise ValueError("workspace ownership is unavailable")
    return {
        CAPTURE_CONTAINER_VARIABLE: ownership.container_name(KALI_CAPTURE_CONTAINER)
    }


def native_kali_ingress(inspected: dict[str, Any], expected_id: str) -> dict[str, str]:
    """Select the workload address; port 22 belongs to the capture broker.

    Native deployments have no legacy Compose SSH proxy. The actual workload
    sshd stays on loopback port 2222 behind the required capture sidecar.
    """
    if (
        not expected_id
        or inspected.get("Id") != expected_id
        or inspected.get("State", {}).get("Running") is not True
    ):
        raise ValueError("native Kali identity is unavailable")
    networks = inspected.get("NetworkSettings", {}).get("Networks", {})
    addresses = sorted(
        str(ip_address(network["IPAddress"]))
        for network in networks.values()
        if network.get("IPAddress")
    )
    if not addresses or ip_address(addresses[0]).is_loopback:
        raise ValueError("native Kali capture ingress is unavailable")
    return {"APTL_MCP_KALI_HOST": addresses[0]}
