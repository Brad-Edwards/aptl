"""Range snapshot capture.

Captures the current state of the lab environment including software
versions, container status, Wazuh rules, network topology, and
configuration file hashes.

All Docker interaction — both container interaction (``container_exec``,
``container_inspect``) and host-level inventory (``host_versions``,
``host_list_lab_containers``, ``host_list_lab_networks``,
``host_inspect_network``) — flows through the deployment backend per
ADR-023, so snapshots taken against an SSH-remote deployment inspect
the remote daemon and behave identically to local Docker Compose.
"""

import hashlib
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from aptl.core.deployment import DeploymentBackend

log = get_logger("snapshot")


@dataclass
class SoftwareVersions(object):
    """Versions of key software components."""

    python_version: str = ""
    docker_version: str = ""
    compose_version: str = ""
    wazuh_manager_version: str = ""
    wazuh_indexer_version: str = ""
    aptl_version: str = ""
    aces_sdl_version: str = ""


@dataclass
class ContainerSnapshot(object):
    """State of a single Docker container."""

    name: str = ""
    image: str = ""
    image_id: str = ""
    status: str = ""
    health: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    networks: dict[str, str] = field(default_factory=dict)
    ports: list[str] = field(default_factory=list)
    image_digest: str = ""


@dataclass
class WazuhRulesSnapshot(object):
    """Summary of Wazuh rule configuration."""

    total_rules: int = 0
    custom_rules: int = 0
    custom_rule_files: list[str] = field(default_factory=list)
    total_decoders: int = 0
    custom_decoders: int = 0


@dataclass
class NetworkSnapshot(object):
    """State of a Docker network."""

    name: str = ""
    subnet: str = ""
    gateway: str = ""
    containers: list[str] = field(default_factory=list)


@dataclass
class ServiceEndpoint(object):
    """A host-accessible service endpoint."""

    name: str = ""
    url: str = ""
    host: str = "localhost"
    port: int = 0
    protocol: str = ""
    credentials: str = ""


@dataclass
class SSHEndpoint(object):
    """An SSH-accessible container."""

    name: str = ""
    host: str = "localhost"
    port: int = 0
    user: str = ""
    key_path: str = "~/.ssh/aptl_lab_key"
    command: str = ""


@dataclass
class RangeSnapshot(object):
    """Complete point-in-time snapshot of the lab range."""

    timestamp: str = ""
    software: SoftwareVersions = field(default_factory=SoftwareVersions)
    containers: list[ContainerSnapshot] = field(default_factory=list)
    wazuh_rules: WazuhRulesSnapshot = field(default_factory=WazuhRulesSnapshot)
    networks: list[NetworkSnapshot] = field(default_factory=list)
    config_hashes: dict[str, str] = field(default_factory=dict)
    services: list[ServiceEndpoint] = field(default_factory=list)
    ssh: list[SSHEndpoint] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary.

        Sensitive fields (service credentials, API tokens, etc.) are
        redacted at this boundary so every caller — `aptl lab status
        --json`, `--output`, future archive writers — gets the same safe
        shape. See ADR-012 § Security Guardrail.
        """
        return redact(asdict(self))


def _backend_exec(
    backend: "DeploymentBackend",
    container: str,
    cmd: list[str],
    timeout: int = 15,
) -> str:
    """Run a one-shot command via the backend; return stripped stdout or empty."""
    try:
        result = backend.container_exec(container, cmd, timeout=timeout)
    except (BackendTimeoutError, OSError) as e:
        log.debug("backend.container_exec %s %s failed: %s", container, cmd, e)
        return ""
    if result.returncode == 0:
        return result.stdout.strip()
    return ""


def _get_software_versions(backend: "DeploymentBackend") -> SoftwareVersions:
    """Collect software version information."""
    versions = SoftwareVersions()

    versions.python_version = sys.version.split()[0]

    daemon_versions = backend.host_versions()
    versions.docker_version = daemon_versions.get("docker", "")
    versions.compose_version = daemon_versions.get("compose", "")

    # Wazuh manager version from container
    wm_out = _backend_exec(
        backend,
        "aptl-wazuh-manager",
        ["/var/ossec/bin/wazuh-control", "info", "-v"],
    )
    if wm_out:
        versions.wazuh_manager_version = wm_out.strip().lstrip("v")

    # Wazuh indexer version (extract from opensearch jar filename)
    wi_out = _backend_exec(
        backend,
        "aptl-wazuh-indexer",
        [
            "bash",
            "-c",
            "ls /usr/share/wazuh-indexer/lib/opensearch-[0-9]*.jar 2>/dev/null | head -1",
        ],
    )
    if wi_out:
        # Extract version from e.g. "opensearch-2.19.1.jar"
        jar_name = Path(wi_out.strip()).name
        ver = jar_name.removeprefix("opensearch-").removesuffix(".jar")
        if ver:
            versions.wazuh_indexer_version = ver

    # APTL version from package metadata
    try:
        from importlib.metadata import PackageNotFoundError, version

        versions.aptl_version = version("aptl")
    except PackageNotFoundError:
        versions.aptl_version = "dev"

    # ACES SDL version from package metadata
    try:
        from importlib.metadata import PackageNotFoundError, version

        versions.aces_sdl_version = version("aces-sdl")
    except PackageNotFoundError:
        versions.aces_sdl_version = ""

    return versions


_HEALTH_MARKERS = (
    ("(healthy)", "healthy"),
    ("(unhealthy)", "unhealthy"),
    ("(health: starting)", "starting"),
)


def _parse_health(status: str) -> str:
    """Map a docker status string to a health label."""
    for marker, label in _HEALTH_MARKERS:
        if marker in status:
            return label
    return ""


def container_networks(
    backend: "DeploymentBackend", name: str
) -> dict[str, str]:
    """Return a container's ``{network_name: IPv4 address}`` map.

    Public because the lab-start SSH readiness step (``lab.py``) needs
    the same per-network IPs the snapshot builder records, to address
    internal-only targets by container IP (issue #293).
    """
    networks: dict[str, str] = {}
    info = backend.container_inspect(name)
    net_data = info.get("NetworkSettings", {}).get("Networks", {})
    if not isinstance(net_data, dict):
        return networks
    for net_name, net_cfg in net_data.items():
        if isinstance(net_cfg, dict):
            ip = net_cfg.get("IPAddress", "")
            if ip:
                networks[net_name] = ip
    return networks


def _row_to_snapshot(
    backend: "DeploymentBackend", row: dict[str, Any]
) -> ContainerSnapshot:
    """Build a ContainerSnapshot from a backend container row."""
    name = row.get("name", "")
    status = row.get("status", "")
    return ContainerSnapshot(
        name=name,
        image=row.get("image", ""),
        image_id=row.get("id", ""),
        status=status,
        health=_parse_health(status),
        labels=row.get("labels", {}),
        networks=container_networks(backend, name),
        ports=row.get("ports", []),
    )


def _get_container_snapshots(
    backend: "DeploymentBackend",
) -> list[ContainerSnapshot]:
    """Snapshot all aptl- containers with network IPs and port mappings.

    Goes through ``backend.host_list_lab_containers`` (and per-container
    ``backend.container_inspect``) so SSH-remote labs enumerate the
    remote daemon. The backend filters by the ``aptl-`` name prefix to
    catch any containers the user named that way even if they're outside
    the current compose project — defensive coverage.
    """
    rows = backend.host_list_lab_containers()
    return [_row_to_snapshot(backend, row) for row in rows]


def list_container_snapshots(
    backend: "DeploymentBackend",
) -> list[ContainerSnapshot]:
    """Public wrapper: snapshot all ``aptl-`` containers with network IPs.

    Consumers that need the per-container network/port inventory without
    building a full :class:`RangeSnapshot` (e.g. the terminal relay's
    endpoint resolution and the lab-start host-key pinning step) call
    this instead of reaching into the private helper.
    """
    return _get_container_snapshots(backend)


def _get_wazuh_rules_snapshot(
    backend: "DeploymentBackend",
) -> WazuhRulesSnapshot:
    """Snapshot Wazuh rule/decoder counts."""
    snap = WazuhRulesSnapshot()
    manager = "aptl-wazuh-manager"

    def _count(query: str) -> int | None:
        """Run a count *query* on the manager; return the int or None."""
        out = _backend_exec(backend, manager, ["bash", "-c", query])
        return int(out) if out.isdigit() else None

    # Count total rules
    snap.total_rules = (
        _count(
            "find /var/ossec/ruleset/rules -name '*.xml' "
            "-exec grep -c '<rule ' {} + 2>/dev/null "
            "| awk -F: '{s+=$NF} END {print s}'"
        )
        or snap.total_rules
    )

    # Count custom rules
    snap.custom_rules = (
        _count(
            "find /var/ossec/etc/rules -name '*.xml' "
            "-exec grep -c '<rule ' {} + 2>/dev/null "
            "| awk -F: '{s+=$NF} END {print s}'"
        )
        or snap.custom_rules
    )

    # List custom rule files
    custom_files = _backend_exec(
        backend,
        manager,
        [
            "bash",
            "-c",
            "ls /var/ossec/etc/rules/*.xml 2>/dev/null",
        ],
    )
    if custom_files:
        snap.custom_rule_files = [
            Path(f).name for f in custom_files.splitlines() if f.strip()
        ]

    # Count total decoders
    snap.total_decoders = (
        _count(
            "find /var/ossec/ruleset/decoders -name '*.xml' "
            "-exec grep -c '<decoder ' {} + 2>/dev/null "
            "| awk -F: '{s+=$NF} END {print s}'"
        )
        or snap.total_decoders
    )

    # Count custom decoders
    snap.custom_decoders = (
        _count(
            "find /var/ossec/etc/decoders -name '*.xml' "
            "-exec grep -c '<decoder ' {} + 2>/dev/null "
            "| awk -F: '{s+=$NF} END {print s}'"
        )
        or snap.custom_decoders
    )

    return snap


def _get_network_snapshots(
    backend: "DeploymentBackend",
) -> list[NetworkSnapshot]:
    """Snapshot Docker networks with aptl prefix."""
    snapshots: list[NetworkSnapshot] = []
    for net_name in backend.host_list_lab_networks("aptl"):
        info = backend.host_inspect_network(net_name)
        snapshots.append(NetworkSnapshot(
            name=net_name,
            subnet=info.get("subnet", ""),
            gateway=info.get("gateway", ""),
            containers=info.get("containers", []),
        ))
    return snapshots


def _hash_config_files(config_dir: Path | None = None) -> dict[str, str]:
    """Compute SHA-256 hashes for config files in the project."""
    hashes = {}

    if config_dir is None:
        config_dir = Path(".")

    patterns = ["aptl.json", "docker-compose*.yml", "docker-compose*.yaml", ".env"]
    for pattern in patterns:
        for f in sorted(config_dir.glob(pattern)):
            if f.is_file():
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
                hashes[f.name] = digest

    return hashes


def detection_content_digest(project_dir: Path) -> str:
    """Compute a combined sha256 digest of detection content under project_dir.

    Hashes Suricata custom rules and Wazuh custom rules found under the
    project directory. Returns an empty string when no detection files are
    found (empty-safe). Reuses the same file-glob/hash pattern as
    :func:`_hash_config_files`.
    """
    patterns = [
        "config/suricata/rules/*.rules",
        "config/suricata/rules/*.conf",
        "config/wazuh/etc/rules/*.xml",
        "config/wazuh/etc/decoders/*.xml",
    ]
    combined = hashlib.sha256()
    found_any = False
    for pattern in patterns:
        for f in sorted(project_dir.glob(pattern)):
            if f.is_file():
                combined.update(f.read_bytes())
                found_any = True
    return combined.hexdigest() if found_any else ""


def capture_snapshot(
    config_dir: Path | None,
    backend: "DeploymentBackend",
) -> RangeSnapshot:
    """Capture a complete snapshot of the current lab state.

    Args:
        config_dir: Directory containing config files to hash. ``None``
                    falls back to the current working directory; pass
                    the project's resolved directory when calling from a
                    CLI command.
        backend: Required deployment backend used for every Docker
                 interaction. The caller is responsible for resolving
                 the right backend (local vs SSH-remote) so the snapshot
                 inspects the daemon the lab actually runs on. There is
                 deliberately no default; a misconfigured caller must
                 fail loudly rather than silently snapshot the local
                 daemon for an SSH-remote lab.

    Returns:
        A RangeSnapshot with all collected data.
    """
    from datetime import datetime, timezone

    from aptl.core.endpoints import (
        build_service_endpoints,
        build_ssh_endpoints,
    )

    log.info("Capturing range snapshot")

    containers = _get_container_snapshots(backend)
    snapshot = RangeSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        software=_get_software_versions(backend),
        containers=containers,
        wazuh_rules=_get_wazuh_rules_snapshot(backend),
        networks=_get_network_snapshots(backend),
        config_hashes=_hash_config_files(config_dir),
        services=build_service_endpoints(containers),
        ssh=build_ssh_endpoints(containers),
    )

    log.info(
        "Snapshot captured: %d containers, %d networks",
        len(snapshot.containers),
        len(snapshot.networks),
    )
    return snapshot
