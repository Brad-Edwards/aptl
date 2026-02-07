"""Connection info generation.

Builds a text block summarizing lab connection details (URLs, SSH
commands, credentials, container IPs) and writes it to a file.
"""

from pathlib import Path

from aptl.core.config import AptlConfig
from aptl.core.env import EnvVars
from aptl.utils.logging import get_logger

log = get_logger("connections")


def generate_connection_info(config: AptlConfig, env: EnvVars) -> str:
    """Build the connection info text block.

    Args:
        config: Validated APTL configuration.
        env: Environment variables with credentials.

    Returns:
        Multi-line string with connection details.
    """
    containers = config.containers
    lines: list[str] = []

    lines.append("")
    lines.append("==========================================")
    lines.append("  APTL Local Lab Started Successfully!")
    lines.append("==========================================")
    lines.append("")

    # Service URLs (only when wazuh is enabled)
    if containers.wazuh:
        lines.append("   Service URLs:")
        lines.append("   Wazuh Dashboard: https://localhost:443")
        lines.append("   Wazuh Indexer: https://localhost:9200")
        lines.append("   Wazuh API: https://172.20.0.10:55000 (internal only)")
        lines.append("")

    # Credentials
    lines.append("   Default Credentials:")
    lines.append(f"   Dashboard: {env.indexer_username} / {env.indexer_password}")
    lines.append(f"   API: {env.api_username} / {env.api_password}")
    lines.append("")

    # SSH Access
    ssh_lines: list[str] = []
    if containers.victim:
        ssh_lines.append(
            "   Victim:          ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022"
        )
    if containers.kali:
        ssh_lines.append(
            "   Kali:            ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023"
        )
    if containers.reverse:
        ssh_lines.append(
            "   Reverse:         ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027"
        )

    if ssh_lines:
        lines.append("   SSH Access:")
        lines.extend(ssh_lines)
        lines.append("")

    # Container IPs
    ip_lines: list[str] = []
    if containers.wazuh:
        ip_lines.append("   wazuh.manager:   172.20.0.10")
        ip_lines.append("   wazuh.dashboard: 172.20.0.11")
        ip_lines.append("   wazuh.indexer:   172.20.0.12")
    if containers.victim:
        ip_lines.append("   victim:          172.20.0.20")
    if containers.kali:
        ip_lines.append("   kali:            172.20.0.30")
    if containers.reverse:
        ip_lines.append("   reverse:         172.20.0.27")

    if ip_lines:
        lines.append("   Container IPs:")
        lines.extend(ip_lines)
        lines.append("")

    lines.append("   Status: Built and ready")
    lines.append("")

    # Management commands
    lines.append("   Management Commands:")
    lines.append("   View logs:    docker compose logs -f [service]")
    lines.append("   Stop lab:     docker compose down")
    lines.append("   Restart:      docker compose restart [service]")
    lines.append("   Full cleanup: docker compose down -v")
    lines.append("")
    lines.append("   Connection info saved to: lab_connections.txt")
    lines.append("")

    return "\n".join(lines)


def write_connection_file(info: str, path: Path) -> None:
    """Write connection info to a file.

    Args:
        info: The connection info text to write.
        path: Output file path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(info)
    path.chmod(0o600)
    log.info("Connection info written to %s", path)
