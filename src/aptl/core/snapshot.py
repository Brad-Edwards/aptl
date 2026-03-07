"""Range snapshot capture.

Captures the current state of the lab environment including software
versions, container status, Wazuh rules, network topology, and
configuration file hashes.
"""

import hashlib
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

from aptl.utils.logging import get_logger

log = get_logger("snapshot")


@dataclass
class SoftwareVersions:
    """Versions of key software components."""

    python_version: str = ""
    docker_version: str = ""
    compose_version: str = ""
    wazuh_manager_version: str = ""
    wazuh_indexer_version: str = ""
    aptl_version: str = ""


@dataclass
class ContainerSnapshot:
    """State of a single Docker container."""

    name: str = ""
    image: str = ""
    image_id: str = ""
    status: str = ""
    health: str = ""
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class WazuhRulesSnapshot:
    """Summary of Wazuh rule configuration."""

    total_rules: int = 0
    custom_rules: int = 0
    custom_rule_files: list[str] = field(default_factory=list)
    total_decoders: int = 0
    custom_decoders: int = 0


@dataclass
class NetworkSnapshot:
    """State of a Docker network."""

    name: str = ""
    subnet: str = ""
    gateway: str = ""
    containers: list[str] = field(default_factory=list)


@dataclass
class RangeSnapshot:
    """Complete point-in-time snapshot of the lab range."""

    timestamp: str = ""
    software: SoftwareVersions = field(default_factory=SoftwareVersions)
    containers: list[ContainerSnapshot] = field(default_factory=list)
    wazuh_rules: WazuhRulesSnapshot = field(default_factory=WazuhRulesSnapshot)
    networks: list[NetworkSnapshot] = field(default_factory=list)
    config_hashes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to a JSON-serializable dictionary."""
        return asdict(self)


def _run_cmd(args: list[str], timeout: int = 15) -> str:
    """Run a command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
        log.debug("Command %s failed: %s", args, e)
    return ""


def _get_software_versions() -> SoftwareVersions:
    """Collect software version information."""
    versions = SoftwareVersions()

    versions.python_version = sys.version.split()[0]

    docker_out = _run_cmd(["docker", "version", "--format", "{{.Server.Version}}"])
    if docker_out:
        versions.docker_version = docker_out

    compose_out = _run_cmd(["docker", "compose", "version", "--short"])
    if compose_out:
        versions.compose_version = compose_out

    # Wazuh manager version from container
    wm_out = _run_cmd([
        "docker", "exec", "aptl-wazuh.manager-1",
        "/var/ossec/bin/wazuh-control", "info", "-v",
    ])
    if wm_out:
        versions.wazuh_manager_version = wm_out.strip().lstrip("v")

    # Wazuh indexer version (extract from opensearch jar filename)
    wi_out = _run_cmd([
        "docker", "exec", "aptl-wazuh.indexer-1",
        "bash", "-c",
        "ls /usr/share/wazuh-indexer/lib/opensearch-[0-9]*.jar 2>/dev/null | head -1",
    ])
    if wi_out:
        # Extract version from e.g. "opensearch-2.19.1.jar"
        jar_name = Path(wi_out.strip()).name
        ver = jar_name.removeprefix("opensearch-").removesuffix(".jar")
        if ver:
            versions.wazuh_indexer_version = ver

    # APTL version from package metadata
    try:
        from importlib.metadata import version

        versions.aptl_version = version("aptl")
    except Exception:
        versions.aptl_version = "dev"

    return versions


def _get_container_snapshots() -> list[ContainerSnapshot]:
    """Snapshot all aptl- containers."""
    fmt = "{{.Names}}\t{{.Image}}\t{{.ID}}\t{{.Status}}\t{{.Labels}}"
    out = _run_cmd([
        "docker", "ps", "-a", "--filter", "name=aptl-", "--format", fmt,
    ])
    if not out:
        return []

    snapshots = []
    for line in out.splitlines():
        parts = line.split("\t", 4)
        if len(parts) < 5:
            continue

        name, image, image_id, status, labels_str = parts

        # Parse health from status string
        health = ""
        if "(healthy)" in status:
            health = "healthy"
        elif "(unhealthy)" in status:
            health = "unhealthy"
        elif "(health: starting)" in status:
            health = "starting"

        # Parse labels
        labels = {}
        if labels_str:
            for pair in labels_str.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    labels[k.strip()] = v.strip()

        snapshots.append(ContainerSnapshot(
            name=name,
            image=image,
            image_id=image_id,
            status=status,
            health=health,
            labels=labels,
        ))

    return snapshots


def _get_wazuh_rules_snapshot() -> WazuhRulesSnapshot:
    """Snapshot Wazuh rule/decoder counts."""
    snap = WazuhRulesSnapshot()

    # Count total rules
    rule_count = _run_cmd([
        "docker", "exec", "aptl-wazuh.manager-1",
        "bash", "-c",
        "find /var/ossec/ruleset/rules -name '*.xml' -exec grep -c '<rule ' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s}'",
    ])
    if rule_count and rule_count.isdigit():
        snap.total_rules = int(rule_count)

    # Count custom rules
    custom_count = _run_cmd([
        "docker", "exec", "aptl-wazuh.manager-1",
        "bash", "-c",
        "find /var/ossec/etc/rules -name '*.xml' -exec grep -c '<rule ' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s}'",
    ])
    if custom_count and custom_count.isdigit():
        snap.custom_rules = int(custom_count)

    # List custom rule files
    custom_files = _run_cmd([
        "docker", "exec", "aptl-wazuh.manager-1",
        "bash", "-c",
        "ls /var/ossec/etc/rules/*.xml 2>/dev/null",
    ])
    if custom_files:
        snap.custom_rule_files = [
            Path(f).name for f in custom_files.splitlines() if f.strip()
        ]

    # Count total decoders
    decoder_count = _run_cmd([
        "docker", "exec", "aptl-wazuh.manager-1",
        "bash", "-c",
        "find /var/ossec/ruleset/decoders -name '*.xml' -exec grep -c '<decoder ' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s}'",
    ])
    if decoder_count and decoder_count.isdigit():
        snap.total_decoders = int(decoder_count)

    # Count custom decoders
    custom_dec = _run_cmd([
        "docker", "exec", "aptl-wazuh.manager-1",
        "bash", "-c",
        "find /var/ossec/etc/decoders -name '*.xml' -exec grep -c '<decoder ' {} + 2>/dev/null | awk -F: '{s+=$NF} END {print s}'",
    ])
    if custom_dec and custom_dec.isdigit():
        snap.custom_decoders = int(custom_dec)

    return snap


def _get_network_snapshots() -> list[NetworkSnapshot]:
    """Snapshot Docker networks with aptl prefix."""
    import json as _json

    out = _run_cmd(["docker", "network", "ls", "--filter", "name=aptl", "--format", "{{.Name}}"])
    if not out:
        return []

    snapshots = []
    for net_name in out.splitlines():
        net_name = net_name.strip()
        if not net_name:
            continue

        inspect_out = _run_cmd(["docker", "network", "inspect", net_name])
        if not inspect_out:
            snapshots.append(NetworkSnapshot(name=net_name))
            continue

        try:
            info = _json.loads(inspect_out)
            if isinstance(info, list) and info:
                info = info[0]

            subnet = ""
            gateway = ""
            ipam_configs = info.get("IPAM", {}).get("Config", [])
            if ipam_configs:
                subnet = ipam_configs[0].get("Subnet", "")
                gateway = ipam_configs[0].get("Gateway", "")

            containers_map = info.get("Containers", {})
            container_names = [
                c.get("Name", "") for c in containers_map.values()
            ]

            snapshots.append(NetworkSnapshot(
                name=net_name,
                subnet=subnet,
                gateway=gateway,
                containers=sorted(container_names),
            ))
        except (_json.JSONDecodeError, KeyError, IndexError) as e:
            log.debug("Failed to parse network inspect for %s: %s", net_name, e)
            snapshots.append(NetworkSnapshot(name=net_name))

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


def capture_snapshot(config_dir: Path | None = None) -> RangeSnapshot:
    """Capture a complete snapshot of the current lab state.

    Args:
        config_dir: Directory containing config files to hash.
                    Defaults to current working directory.

    Returns:
        A RangeSnapshot with all collected data.
    """
    from datetime import datetime, timezone

    log.info("Capturing range snapshot")

    snapshot = RangeSnapshot(
        timestamp=datetime.now(timezone.utc).isoformat(),
        software=_get_software_versions(),
        containers=_get_container_snapshots(),
        wazuh_rules=_get_wazuh_rules_snapshot(),
        networks=_get_network_snapshots(),
        config_hashes=_hash_config_files(config_dir),
    )

    log.info(
        "Snapshot captured: %d containers, %d networks",
        len(snapshot.containers),
        len(snapshot.networks),
    )
    return snapshot
