"""Derive native Kali MCP ingress from the admitted guest Docker runtime."""

from ipaddress import ip_address


def native_kali_ingress(inspected: dict, expected_id: str) -> dict[str, str]:
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
