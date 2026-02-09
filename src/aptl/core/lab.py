"""Lab lifecycle management.

Wraps docker compose commands for starting, stopping, and checking lab status.
All Docker interactions go through subprocess calls to docker compose.
Includes the full orchestration of lab startup (equivalent of start-lab.sh).
"""

import json
import subprocess
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Optional

from aptl.core.certs import ensure_ssl_certs
from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.connections import generate_connection_info, write_connection_file
from aptl.core.credentials import sync_dashboard_config, sync_manager_config
from aptl.core.env import EnvVars, env_vars_from_dict, load_dotenv
from aptl.core.services import (
    check_indexer_ready,
    check_manager_api_ready,
    test_ssh_connection,
    wait_for_service,
)
from aptl.core.ssh import ensure_ssh_keys
from aptl.core.sysreqs import check_max_map_count
from aptl.utils.logging import get_logger

log = get_logger("lab")


@dataclass
class LabResult:
    """Result of a lab lifecycle operation."""

    success: bool
    message: str = ""
    error: str = ""


@dataclass
class LabStatus:
    """Current status of the lab environment."""

    running: bool
    containers: list[dict] = field(default_factory=list)
    error: str = ""


def docker_client():
    """Get a Docker client. Separated for easy mocking."""
    import docker  # noqa: delayed import for mocking
    return docker.from_env()


def build_compose_command(
    action: str,
    profiles: list[str],
) -> list[str]:
    """Build a docker compose command with profile flags.

    Args:
        action: The compose action (up, down, ps, etc.).
        profiles: List of docker compose profiles to activate.

    Returns:
        Command as a list of strings suitable for subprocess.run().
    """
    cmd = ["docker", "compose"]

    for profile in profiles:
        cmd.extend(["--profile", profile])

    cmd.append(action)

    if action == "up":
        cmd.extend(["--build", "-d"])

    return cmd


def start_lab(
    config: AptlConfig,
    project_dir: Optional[Path] = None,
) -> LabResult:
    """Start the lab environment using docker compose.

    Args:
        config: Validated APTL configuration.
        project_dir: Working directory for docker compose (where docker-compose.yml lives).

    Returns:
        LabResult indicating success or failure.
    """
    profiles = config.containers.enabled_profiles()
    cmd = build_compose_command("up", profiles)

    log.info("Starting lab with profiles: %s", profiles)
    log.debug("Command: %s", " ".join(cmd))

    kwargs: dict = {"capture_output": True, "text": True}
    if project_dir is not None:
        kwargs["cwd"] = project_dir

    result = subprocess.run(cmd, **kwargs)

    if result.returncode != 0:
        log.error("Lab start failed: %s", result.stderr)
        return LabResult(success=False, error=result.stderr)

    log.info("Lab started successfully")
    return LabResult(success=True, message="Lab started")


def stop_lab(
    remove_volumes: bool = False,
    project_dir: Optional[Path] = None,
) -> LabResult:
    """Stop the lab environment.

    Loads the config to determine which profiles to include in the
    down command. If config loading fails, falls back to all known
    profiles to ensure containers are stopped.

    Args:
        remove_volumes: If True, also remove Docker volumes (-v flag).
        project_dir: Working directory for docker compose.

    Returns:
        LabResult indicating success or failure.
    """
    # Load config to get active profiles; fall back to all profiles
    profiles: list[str] = []
    search_dir = project_dir or Path(".")
    config_path = find_config(search_dir)
    if config_path is not None:
        try:
            config = load_config(config_path)
            profiles = config.containers.enabled_profiles()
        except (FileNotFoundError, ValueError) as exc:
            log.warning("Could not load config for profiles: %s", exc)
    if not profiles:
        profiles = ["wazuh", "victim", "kali", "reverse"]

    cmd = build_compose_command("down", profiles=profiles)
    if remove_volumes:
        cmd.append("-v")

    log.info("Stopping lab (remove_volumes=%s)", remove_volumes)

    kwargs: dict = {"capture_output": True, "text": True}
    if project_dir is not None:
        kwargs["cwd"] = project_dir

    result = subprocess.run(cmd, **kwargs)

    if result.returncode != 0:
        log.error("Lab stop failed: %s", result.stderr)
        return LabResult(success=False, error=result.stderr)

    log.info("Lab stopped successfully")
    return LabResult(success=True, message="Lab stopped")


def lab_status(
    project_dir: Optional[Path] = None,
) -> LabStatus:
    """Get the current lab status by querying docker compose.

    Args:
        project_dir: Working directory for docker compose.

    Returns:
        LabStatus with container information.
    """
    cmd = ["docker", "compose", "ps", "--format", "json"]

    kwargs: dict = {"capture_output": True, "text": True}
    if project_dir is not None:
        kwargs["cwd"] = project_dir

    result = subprocess.run(cmd, **kwargs)

    if result.returncode != 0:
        log.warning("Could not get lab status: %s", result.stderr)
        return LabStatus(running=False, error=result.stderr)

    try:
        # docker compose ps --format json outputs one JSON object per line
        # (NDJSON), not a JSON array. Try array first, fall back to NDJSON.
        stripped = result.stdout.strip()
        if not stripped:
            containers = []
        elif stripped.startswith("["):
            containers = json.loads(stripped)
        else:
            containers = [json.loads(line) for line in stripped.splitlines() if line.strip()]
    except json.JSONDecodeError:
        log.warning("Could not parse compose ps output")
        return LabStatus(running=False, error="Failed to parse container status")

    running = len(containers) > 0
    return LabStatus(running=running, containers=containers)


def orchestrate_lab_start(project_dir: Path) -> LabResult:
    """Orchestrate the complete lab startup process.

    This is the Python equivalent of start-lab.sh. It performs all steps
    in order:
      1. Load and validate .env
      2. Load and validate aptl.json config
      3. Generate SSH keys
      4. Check system requirements
      5. Sync config file credentials
      6. Generate SSL certificates
      7. Pre-pull container images
      8. Start containers via docker compose
      9. Wait for services to become ready
     10. Test SSH connectivity
     11. Generate connection info
     12. Build MCP servers

    Args:
        project_dir: Root directory of the APTL project.

    Returns:
        LabResult indicating overall success or failure.
    """
    log.info("Starting APTL lab from %s", project_dir)

    # Step 1: Load .env
    log.info("Step 1: Loading environment variables...")
    env_path = project_dir / ".env"
    try:
        raw_env = load_dotenv(env_path)
        env = env_vars_from_dict(raw_env)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Failed to load .env: %s", exc)
        return LabResult(success=False, error=f"Failed to load .env: {exc}")

    # Step 2: Load aptl.json config
    log.info("Step 2: Loading configuration...")
    config_path = find_config(project_dir)
    if config_path is None:
        log.error("No aptl.json found in %s", project_dir)
        return LabResult(
            success=False,
            error=f"Config file aptl.json not found in {project_dir}",
        )
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Failed to load config: %s", exc)
        return LabResult(success=False, error=f"Failed to load config: {exc}")

    # Step 3: Generate SSH keys
    log.info("Step 3: Generating SSH keys...")
    keys_dir = project_dir / "containers" / "keys"
    host_ssh_dir = Path.home() / ".ssh"
    ssh_result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)
    if not ssh_result.success:
        log.error("SSH key generation failed: %s", ssh_result.error)
        return LabResult(
            success=False,
            error=f"SSH key generation failed: {ssh_result.error}",
        )

    # Step 4: Check system requirements
    log.info("Step 4: Checking system requirements...")
    sysreq_result = check_max_map_count()
    if not sysreq_result.passed:
        log.error(
            "vm.max_map_count too low (%d < %d). Run: sudo sysctl -w vm.max_map_count=262144",
            sysreq_result.current_value,
            sysreq_result.required_value,
        )
        return LabResult(
            success=False,
            error=(
                f"vm.max_map_count too low ({sysreq_result.current_value} < "
                f"{sysreq_result.required_value}). "
                "Run: sudo sysctl -w vm.max_map_count=262144"
            ),
        )

    # Step 5: Sync config file credentials
    log.info("Step 5: Syncing configuration credentials...")
    dashboard_config = project_dir / "config" / "wazuh_dashboard" / "wazuh.yml"
    if dashboard_config.exists():
        try:
            sync_dashboard_config(dashboard_config, env.api_password)
        except Exception as exc:
            log.warning("Failed to sync dashboard config: %s", exc)
    else:
        log.warning("Dashboard config not found at %s", dashboard_config)

    manager_config = project_dir / "config" / "wazuh_cluster" / "wazuh_manager.conf"
    if manager_config.exists():
        try:
            sync_manager_config(manager_config, env.wazuh_cluster_key)
        except Exception as exc:
            log.warning("Failed to sync manager config: %s", exc)
    else:
        log.warning("Manager config not found at %s", manager_config)

    # Step 6: Generate SSL certificates
    log.info("Step 6: Generating SSL certificates...")
    cert_result = ensure_ssl_certs(project_dir)
    if not cert_result.success:
        log.error("Certificate generation failed: %s", cert_result.error)
        return LabResult(
            success=False,
            error=f"Certificate generation failed: {cert_result.error}",
        )

    # Step 7: Pre-pull container images (non-critical)
    log.info("Step 7: Pre-pulling container images...")
    images = [
        "wazuh/wazuh-manager:4.9.2",
        "wazuh/wazuh-indexer:4.9.2",
        "wazuh/wazuh-dashboard:4.9.2",
    ]
    for image in images:
        try:
            pull_result = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                cwd=project_dir,
            )
            if pull_result.returncode != 0:
                log.warning("Failed to pull %s: %s", image, pull_result.stderr.strip())
            else:
                log.info("Pulled %s", image)
        except (FileNotFoundError, OSError) as exc:
            log.warning("Failed to pull %s: %s", image, exc)

    # Step 8: Start containers
    log.info("Step 8: Starting containers...")
    start_result = start_lab(config, project_dir=project_dir)
    if not start_result.success:
        log.error("Lab start failed: %s", start_result.error)
        return LabResult(
            success=False,
            error=f"Lab start failed: {start_result.error}",
        )

    # Step 9: Wait for services
    log.info("Step 9: Waiting for services...")
    if config.containers.wazuh:
        indexer_result = wait_for_service(
            check_fn=partial(
                check_indexer_ready,
                url="https://localhost:9200",
                username=env.indexer_username,
                password=env.indexer_password,
            ),
            timeout=300,
            interval=10,
            service_name="Wazuh Indexer",
        )
        if not indexer_result.ready:
            log.warning("Indexer may still be initializing")

        manager_result = wait_for_service(
            check_fn=partial(
                check_manager_api_ready,
                container_name="aptl-wazuh.manager-1",
                username=env.api_username,
                password=env.api_password,
            ),
            timeout=120,
            interval=5,
            service_name="Wazuh Manager API",
        )
        if not manager_result.ready:
            log.warning("Manager API may still be initializing")

    # Step 10: Test SSH connectivity (non-critical)
    log.info("Step 10: Testing SSH connectivity...")
    key_path = ssh_result.key_path or (Path.home() / ".ssh" / "aptl_lab_key")
    ssh_tests = []
    if config.containers.victim:
        ssh_tests.append(("victim", 2022, "labadmin"))
    if config.containers.kali:
        ssh_tests.append(("kali", 2023, "kali"))
    if config.containers.reverse:
        ssh_tests.append(("reverse", 2027, "labadmin"))

    for name, port, user in ssh_tests:
        ok = test_ssh_connection(
            host="localhost", port=port, user=user, key_path=key_path
        )
        if ok:
            log.info("SSH to %s is ready", name)
        else:
            log.warning("SSH to %s not ready yet (may need more time)", name)

    # Step 11: Generate connection info
    log.info("Step 11: Generating connection info...")
    info = generate_connection_info(config, env)
    write_connection_file(info, project_dir / "lab_connections.txt")
    log.info("\n%s", info)

    # Step 12: Build MCP servers (non-critical)
    log.info("Step 12: Building MCP servers...")
    mcp_script = project_dir / "mcp" / "build-all-mcps.sh"
    if mcp_script.exists():
        try:
            mcp_result = subprocess.run(
                [str(mcp_script)],
                capture_output=True,
                text=True,
                cwd=project_dir,
            )
            if mcp_result.returncode != 0:
                log.warning("MCP build had errors: %s", mcp_result.stderr)
            else:
                log.info("MCP servers built successfully")
        except (FileNotFoundError, OSError) as exc:
            log.warning("Failed to build MCP servers: %s", exc)
    else:
        log.warning("MCP build script not found at %s", mcp_script)

    log.info("APTL lab started successfully!")
    return LabResult(success=True, message="Lab started successfully")
