"""Experiment run management, range snapshots, and manifests.

An *experiment* wraps one or more scenario runs with full state capture:
  1. Snapshot the range (container images, Wazuh rules, configs, versions).
  2. Run the scenario (delegating to the existing scenario lifecycle).
  3. Collect all artefacts (alerts, logs, events, CLI activity).
  4. Package the run for export (local tar.gz or S3).
  5. Reset the range for the next run.

The experiment directory layout inside .aptl/experiments/<run_id>/:
    manifest.json           -- Run metadata and checksums
    range_snapshot/         -- Pre-run state capture
    scenario/               -- Copy of the scenario YAML
    events/                 -- JSONL event timeline
    logs/                   -- Container logs captured post-run
    alerts/                 -- Wazuh alerts during the run window
    report/                 -- Scenario after-action report
    detection/              -- Detection coverage results
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

import yaml

from aptl.utils.logging import get_logger

log = get_logger("experiment")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class SoftwareVersions:
    """Versions of key software on the host and in containers."""

    python: str = ""
    docker: str = ""
    docker_compose: str = ""
    wazuh_manager: str = ""
    wazuh_indexer: str = ""
    os_platform: str = ""
    os_release: str = ""
    aptl_version: str = ""


@dataclass
class ContainerSnapshot:
    """Snapshot of a single container at capture time."""

    name: str
    image: str = ""
    image_id: str = ""
    state: str = ""
    health: str = ""
    created: str = ""
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class WazuhRulesSnapshot:
    """Snapshot of active Wazuh rules and decoders."""

    rules_count: int = 0
    custom_rules_count: int = 0
    decoders_count: int = 0
    custom_decoders_count: int = 0
    rules_files: list[str] = field(default_factory=list)
    custom_rules_files: list[str] = field(default_factory=list)


@dataclass
class NetworkSnapshot:
    """Docker network configuration at capture time."""

    networks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RangeSnapshot:
    """Complete snapshot of the lab range state before an experiment run.

    Captures everything needed to reproduce the range state: software
    versions, container images, Wazuh rules, network config, and the
    configuration files themselves.
    """

    captured_at: str = ""
    software_versions: SoftwareVersions = field(default_factory=SoftwareVersions)
    containers: list[ContainerSnapshot] = field(default_factory=list)
    wazuh_rules: WazuhRulesSnapshot = field(default_factory=WazuhRulesSnapshot)
    network: NetworkSnapshot = field(default_factory=NetworkSnapshot)
    aptl_config: dict[str, Any] = field(default_factory=dict)
    docker_compose_hash: str = ""
    env_vars_hash: str = ""


@dataclass
class ExperimentManifest:
    """Metadata and integrity information for an experiment run.

    Written as manifest.json at the root of each experiment directory.
    """

    run_id: str = ""
    scenario_id: str = ""
    scenario_name: str = ""
    scenario_version: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    range_snapshot_hash: str = ""
    artefact_checksums: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    notes: str = ""


# ---------------------------------------------------------------------------
# Snapshot capture
# ---------------------------------------------------------------------------


def _run_cmd(cmd: list[str], timeout: int = 30) -> str:
    """Run a command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""


def _file_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _content_sha256(content: str) -> str:
    """Compute SHA-256 hex digest of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def capture_software_versions(project_dir: Path) -> SoftwareVersions:
    """Capture versions of key software."""
    import aptl

    docker_version = _run_cmd(["docker", "--version"])
    compose_version = _run_cmd(["docker", "compose", "version"])

    # Wazuh versions from running containers
    wazuh_mgr_version = _run_cmd([
        "docker", "exec", "aptl-wazuh.manager-1",
        "/var/ossec/bin/wazuh-control", "info", "-v",
    ])
    wazuh_idx_version = _run_cmd([
        "docker", "exec", "aptl-wazuh.indexer-1",
        "cat", "/usr/share/wazuh-indexer/VERSION",
    ])

    return SoftwareVersions(
        python=platform.python_version(),
        docker=docker_version,
        docker_compose=compose_version,
        wazuh_manager=wazuh_mgr_version,
        wazuh_indexer=wazuh_idx_version,
        os_platform=platform.platform(),
        os_release=platform.release(),
        aptl_version=getattr(aptl, "__version__", "unknown"),
    )


def capture_container_state() -> list[ContainerSnapshot]:
    """Capture the state of all running containers."""
    raw = _run_cmd([
        "docker", "compose", "ps", "--format", "json",
    ])
    if not raw:
        return []

    containers: list[ContainerSnapshot] = []
    try:
        if raw.startswith("["):
            items = json.loads(raw)
        else:
            items = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except json.JSONDecodeError:
        return []

    for item in items:
        name = item.get("Name", item.get("name", ""))
        # Get detailed image info via docker inspect
        image_id = ""
        labels: dict[str, str] = {}
        inspect_raw = _run_cmd(["docker", "inspect", name, "--format", "json"])
        if inspect_raw:
            try:
                inspect_data = json.loads(inspect_raw)
                if isinstance(inspect_data, list) and inspect_data:
                    detail = inspect_data[0]
                    image_id = detail.get("Image", "")
                    labels = detail.get("Config", {}).get("Labels", {}) or {}
            except json.JSONDecodeError:
                pass

        containers.append(ContainerSnapshot(
            name=name,
            image=item.get("Image", item.get("image", "")),
            image_id=image_id,
            state=item.get("State", item.get("state", "")),
            health=item.get("Health", item.get("health", "")),
            created=item.get("CreatedAt", item.get("created", "")),
            labels=labels,
        ))

    return containers


def capture_wazuh_rules() -> WazuhRulesSnapshot:
    """Capture Wazuh rules and decoders inventory from the manager container."""
    manager = "aptl-wazuh.manager-1"

    # Count rules
    rules_output = _run_cmd([
        "docker", "exec", manager, "sh", "-c",
        "find /var/ossec/ruleset/rules -name '*.xml' | wc -l",
    ])
    custom_rules_output = _run_cmd([
        "docker", "exec", manager, "sh", "-c",
        "find /var/ossec/etc/rules -name '*.xml' 2>/dev/null | wc -l",
    ])
    decoders_output = _run_cmd([
        "docker", "exec", manager, "sh", "-c",
        "find /var/ossec/ruleset/decoders -name '*.xml' | wc -l",
    ])
    custom_decoders_output = _run_cmd([
        "docker", "exec", manager, "sh", "-c",
        "find /var/ossec/etc/decoders -name '*.xml' 2>/dev/null | wc -l",
    ])

    # List custom rules files
    rules_files_raw = _run_cmd([
        "docker", "exec", manager, "sh", "-c",
        "find /var/ossec/etc/rules -name '*.xml' 2>/dev/null",
    ])
    custom_rules_files = [
        f for f in rules_files_raw.splitlines() if f.strip()
    ]

    # List built-in rules files
    builtin_rules_raw = _run_cmd([
        "docker", "exec", manager, "sh", "-c",
        "find /var/ossec/ruleset/rules -name '*.xml' -exec basename {} \\;",
    ])
    rules_files = [f for f in builtin_rules_raw.splitlines() if f.strip()]

    def _safe_int(s: str) -> int:
        try:
            return int(s.strip())
        except (ValueError, AttributeError):
            return 0

    return WazuhRulesSnapshot(
        rules_count=_safe_int(rules_output),
        custom_rules_count=_safe_int(custom_rules_output),
        decoders_count=_safe_int(decoders_output),
        custom_decoders_count=_safe_int(custom_decoders_output),
        rules_files=rules_files,
        custom_rules_files=custom_rules_files,
    )


def capture_network_state() -> NetworkSnapshot:
    """Capture Docker network configuration."""
    raw = _run_cmd(["docker", "network", "ls", "--format", "json"])
    if not raw:
        return NetworkSnapshot()

    networks: list[dict[str, Any]] = []
    try:
        lines = raw.splitlines()
        for line in lines:
            if not line.strip():
                continue
            net = json.loads(line)
            name = net.get("Name", "")
            if "aptl" in name.lower():
                # Get detailed network info
                inspect_raw = _run_cmd([
                    "docker", "network", "inspect", name, "--format", "json",
                ])
                if inspect_raw:
                    try:
                        detail = json.loads(inspect_raw)
                        if isinstance(detail, list) and detail:
                            networks.append(detail[0])
                        else:
                            networks.append(detail)
                    except json.JSONDecodeError:
                        networks.append(net)
                else:
                    networks.append(net)
    except json.JSONDecodeError:
        pass

    return NetworkSnapshot(networks=networks)


def capture_range_snapshot(project_dir: Path) -> RangeSnapshot:
    """Capture a complete range snapshot.

    Gathers software versions, container state, Wazuh rules, network
    configuration, and hashes of key config files.

    Args:
        project_dir: Root directory of the APTL project.

    Returns:
        RangeSnapshot with all captured state.
    """
    log.info("Capturing range snapshot...")

    software = capture_software_versions(project_dir)
    containers = capture_container_state()
    wazuh_rules = capture_wazuh_rules()
    network = capture_network_state()

    # Load aptl.json if present
    aptl_config: dict[str, Any] = {}
    config_path = project_dir / "aptl.json"
    if config_path.exists():
        try:
            aptl_config = json.loads(config_path.read_text())
        except json.JSONDecodeError:
            log.warning("Failed to parse aptl.json for snapshot")

    # Hash key config files
    compose_hash = _file_sha256(project_dir / "docker-compose.yml")
    env_hash = _file_sha256(project_dir / ".env")

    snapshot = RangeSnapshot(
        captured_at=datetime.now(timezone.utc).isoformat(),
        software_versions=software,
        containers=containers,
        wazuh_rules=wazuh_rules,
        network=network,
        aptl_config=aptl_config,
        docker_compose_hash=compose_hash,
        env_vars_hash=env_hash,
    )

    log.info(
        "Range snapshot captured: %d containers, %d rules",
        len(containers),
        wazuh_rules.rules_count,
    )
    return snapshot


# ---------------------------------------------------------------------------
# Experiment directory management
# ---------------------------------------------------------------------------


def generate_run_id() -> str:
    """Generate a unique experiment run ID.

    Format: YYYYMMDD-HHMMSS-<short_uuid>
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    short = uuid4().hex[:8]
    return f"{ts}-{short}"


def experiment_dir(state_dir: Path, run_id: str) -> Path:
    """Return the experiment directory for a given run ID."""
    return state_dir / "experiments" / run_id


def create_experiment_dir(state_dir: Path, run_id: str) -> Path:
    """Create the experiment directory structure.

    Creates:
        .aptl/experiments/<run_id>/
            range_snapshot/
            scenario/
            events/
            logs/
            alerts/
            report/
            detection/

    Returns:
        Path to the experiment root directory.
    """
    exp_dir = experiment_dir(state_dir, run_id)
    for subdir in [
        "range_snapshot", "scenario", "events", "logs",
        "alerts", "report", "detection",
    ]:
        (exp_dir / subdir).mkdir(parents=True, exist_ok=True)
    log.info("Created experiment directory: %s", exp_dir)
    return exp_dir


def write_snapshot(exp_dir: Path, snapshot: RangeSnapshot) -> Path:
    """Write the range snapshot to the experiment directory.

    Returns:
        Path to the written snapshot file.
    """
    snapshot_path = exp_dir / "range_snapshot" / "snapshot.json"
    snapshot_path.write_text(
        json.dumps(asdict(snapshot), indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    log.info("Wrote range snapshot to %s", snapshot_path)
    return snapshot_path


def write_manifest(exp_dir: Path, manifest: ExperimentManifest) -> Path:
    """Write the experiment manifest to the experiment directory.

    Returns:
        Path to the written manifest file.
    """
    manifest_path = exp_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(asdict(manifest), indent=2) + "\n",
        encoding="utf-8",
    )
    log.info("Wrote experiment manifest to %s", manifest_path)
    return manifest_path


def copy_scenario_yaml(
    exp_dir: Path,
    scenario_path: Path,
) -> Path:
    """Copy the scenario YAML into the experiment directory.

    Returns:
        Path to the copied file.
    """
    dest = exp_dir / "scenario" / scenario_path.name
    shutil.copy2(scenario_path, dest)
    log.info("Copied scenario YAML to %s", dest)
    return dest


def copy_docker_compose(exp_dir: Path, project_dir: Path) -> Optional[Path]:
    """Copy docker-compose.yml into the range snapshot."""
    src = project_dir / "docker-compose.yml"
    if not src.exists():
        return None
    dest = exp_dir / "range_snapshot" / "docker-compose.yml"
    shutil.copy2(src, dest)
    return dest


def copy_aptl_config(exp_dir: Path, project_dir: Path) -> Optional[Path]:
    """Copy aptl.json into the range snapshot."""
    src = project_dir / "aptl.json"
    if not src.exists():
        return None
    dest = exp_dir / "range_snapshot" / "aptl.json"
    shutil.copy2(src, dest)
    return dest


def copy_wazuh_configs(exp_dir: Path, project_dir: Path) -> list[Path]:
    """Copy Wazuh configuration files into the range snapshot."""
    copied: list[Path] = []
    config_dir = project_dir / "config"
    if not config_dir.exists():
        return copied

    dest_dir = exp_dir / "range_snapshot" / "wazuh_config"
    dest_dir.mkdir(parents=True, exist_ok=True)

    for config_file in config_dir.rglob("*"):
        if config_file.is_file() and config_file.suffix in (
            ".conf", ".yml", ".yaml", ".xml", ".json",
        ):
            relative = config_file.relative_to(config_dir)
            dest = dest_dir / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(config_file, dest)
            copied.append(dest)

    return copied


def copy_pyproject(exp_dir: Path, project_dir: Path) -> Optional[Path]:
    """Copy pyproject.toml into the range snapshot."""
    src = project_dir / "pyproject.toml"
    if not src.exists():
        return None
    dest = exp_dir / "range_snapshot" / "pyproject.toml"
    shutil.copy2(src, dest)
    return dest


# ---------------------------------------------------------------------------
# Range reset
# ---------------------------------------------------------------------------


def reset_range(
    project_dir: Path,
    *,
    flush_wazuh_indices: bool = False,
    restart_containers: list[str] | None = None,
) -> dict[str, Any]:
    """Reset the range for the next experiment run.

    Performs a fast reset without full lab restart:
      1. Clear .aptl/session.json (scenario state).
      2. Optionally flush Wazuh alert indices for the run time window.
      3. Optionally restart specific containers.

    Args:
        project_dir: Root directory of the APTL project.
        flush_wazuh_indices: If True, delete recent alerts from Wazuh.
        restart_containers: List of container names to restart.

    Returns:
        Dict summarizing what was reset.
    """
    log.info("Resetting range for next experiment...")
    result: dict[str, Any] = {
        "session_cleared": False,
        "indices_flushed": False,
        "containers_restarted": [],
    }

    # 1. Clear session state
    session_path = project_dir / ".aptl" / "session.json"
    if session_path.exists():
        session_path.unlink()
        result["session_cleared"] = True
        log.info("Cleared session state")

    # 2. Optionally flush Wazuh indices
    if flush_wazuh_indices:
        flush_result = _run_cmd([
            "docker", "exec", "aptl-wazuh.indexer-1",
            "sh", "-c",
            (
                "curl -s -k -u admin:SecretPassword "
                "-X POST 'https://localhost:9200/wazuh-alerts-4.x-*/_delete_by_query' "
                "-H 'Content-Type: application/json' "
                "-d '{\"query\":{\"match_all\":{}}}'"
            ),
        ])
        result["indices_flushed"] = bool(flush_result)
        log.info("Flushed Wazuh alert indices")

    # 3. Optionally restart containers
    if restart_containers:
        for container in restart_containers:
            restart_out = _run_cmd(["docker", "restart", container])
            if restart_out is not None:
                result["containers_restarted"].append(container)
                log.info("Restarted container: %s", container)

    log.info("Range reset complete")
    return result


# ---------------------------------------------------------------------------
# Experiment listing
# ---------------------------------------------------------------------------


def list_experiments(state_dir: Path) -> list[ExperimentManifest]:
    """List all completed experiments.

    Args:
        state_dir: The .aptl/ state directory.

    Returns:
        List of ExperimentManifest objects sorted by start time.
    """
    experiments_dir = state_dir / "experiments"
    if not experiments_dir.exists():
        return []

    manifests: list[ExperimentManifest] = []
    for run_dir in sorted(experiments_dir.iterdir()):
        manifest_path = run_dir / "manifest.json"
        if manifest_path.exists():
            try:
                data = json.loads(manifest_path.read_text())
                manifest = ExperimentManifest(**data)
                manifests.append(manifest)
            except (json.JSONDecodeError, TypeError) as e:
                log.warning("Skipping malformed manifest in %s: %s", run_dir, e)

    return manifests


def load_manifest(state_dir: Path, run_id: str) -> Optional[ExperimentManifest]:
    """Load a specific experiment manifest.

    Args:
        state_dir: The .aptl/ state directory.
        run_id: The experiment run ID.

    Returns:
        ExperimentManifest or None if not found.
    """
    manifest_path = experiment_dir(state_dir, run_id) / "manifest.json"
    if not manifest_path.exists():
        return None

    try:
        data = json.loads(manifest_path.read_text())
        return ExperimentManifest(**data)
    except (json.JSONDecodeError, TypeError):
        return None
