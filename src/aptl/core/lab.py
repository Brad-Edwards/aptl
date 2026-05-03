"""Lab lifecycle management.

Wraps deployment backends for starting, stopping, and checking lab status.
Docker interactions go through the DeploymentBackend protocol, with Docker
Compose as the default backend.  Includes the full orchestration of lab
startup.
"""

import subprocess
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import yaml

from aptl.core.certs import ensure_ssl_certs
from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.credentials import sync_dashboard_config, sync_manager_config
from aptl.core.env import (
    EnvVars,
    env_vars_from_dict,
    find_placeholder_env_values,
    load_dotenv,
)
from aptl.core.services import (
    check_indexer_ready,
    check_manager_api_ready,
    test_ssh_connection,
    wait_for_service,
)
from aptl.core.snapshot import capture_snapshot
from aptl.core.ssh import ensure_ssh_keys
from aptl.core.sysreqs import check_max_map_count
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("lab")

WAZUH_IMAGE_VERSION = "4.12.0"

# All known Docker Compose profiles. Used as fallback when config is
# unavailable (e.g. stop_lab, kill switch).  Keep in sync with
# docker-compose.yml profile definitions.
ALL_KNOWN_PROFILES = [
    "wazuh", "victim", "kali", "reverse",
    "enterprise", "soc", "mail", "fileshare", "dns",
    "otel",
]


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


def _get_backend(
    project_dir: Path,
    config: AptlConfig | None = None,
) -> "DeploymentBackend":
    """Create a deployment backend from config or defaults.

    Args:
        project_dir: Working directory for the deployment.
        config: Optional config; if None, uses default Docker Compose.

    Returns:
        A DeploymentBackend instance.
    """
    from aptl.core.deployment import get_backend
    from aptl.core.deployment.docker_compose import DockerComposeBackend

    if config is not None:
        return get_backend(config, project_dir)
    return DockerComposeBackend(project_dir=project_dir)


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
    backend: Optional["DeploymentBackend"] = None,
) -> LabResult:
    """Start the lab environment.

    Delegates to the deployment backend.  If no backend is provided,
    one is created from the config.

    Args:
        config: Validated APTL configuration.
        project_dir: Working directory (where docker-compose.yml lives).
        backend: Optional pre-created deployment backend.

    Returns:
        LabResult indicating success or failure.
    """
    profiles = config.containers.enabled_profiles()
    # OTel stack (Collector + Tempo + Grafana) is core infrastructure
    if "otel" not in profiles:
        profiles = [*profiles, "otel"]

    if backend is None:
        resolved_dir = project_dir or Path(".")
        backend = _get_backend(resolved_dir, config)

    return backend.start(profiles)


def stop_lab(
    remove_volumes: bool = False,
    project_dir: Optional[Path] = None,
    backend: Optional["DeploymentBackend"] = None,
) -> LabResult:
    """Stop the lab environment.

    Loads the config to determine which profiles to include in the
    down command. If config loading fails, falls back to all known
    profiles to ensure containers are stopped.

    Args:
        remove_volumes: If True, also remove Docker volumes (-v flag).
        project_dir: Working directory for the deployment.
        backend: Optional pre-created deployment backend.

    Returns:
        LabResult indicating success or failure.
    """
    # Load config to get active profiles; fall back to all profiles
    profiles: list[str] = []
    search_dir = project_dir or Path(".")
    config_path = find_config(search_dir)
    config: AptlConfig | None = None
    if config_path is not None:
        try:
            config = load_config(config_path)
            profiles = config.containers.enabled_profiles()
        except (FileNotFoundError, ValueError) as exc:
            log.warning("Could not load config for profiles: %s", exc)
    if not profiles:
        profiles = list(ALL_KNOWN_PROFILES)

    if backend is None:
        backend = _get_backend(search_dir, config)

    return backend.stop(profiles, remove_volumes=remove_volumes)


def lab_status(
    project_dir: Optional[Path] = None,
    backend: Optional["DeploymentBackend"] = None,
) -> LabStatus:
    """Get the current lab status.

    Delegates to the deployment backend.

    Args:
        project_dir: Working directory for the deployment.
        backend: Optional pre-created deployment backend.

    Returns:
        LabStatus with container information.
    """
    resolved_dir = project_dir or Path(".")

    if backend is None:
        backend = _get_backend(resolved_dir)

    return backend.status()


def _check_bind_mounts(project_dir: Path) -> list[str]:
    """Check that bind-mount source paths exist as files, not root-owned dirs.

    Parses docker-compose.yml for relative bind mounts (``./`` prefix) and
    verifies that each source path exists. Returns a list of error messages
    for any missing sources so the caller can fail early instead of letting
    Docker silently create root-owned directories.
    """
    compose_path = project_dir / "docker-compose.yml"
    if not compose_path.exists():
        log.debug("No docker-compose.yml found, skipping bind-mount check")
        return []

    try:
        data = yaml.safe_load(compose_path.read_text())
    except yaml.YAMLError as e:
        return [f"Failed to parse docker-compose.yml: {e}"]

    errors: list[str] = []
    services = data.get("services", {}) if isinstance(data, dict) else {}
    for svc_name, svc_def in services.items():
        if not isinstance(svc_def, dict):
            continue
        for vol in svc_def.get("volumes", []):
            if isinstance(vol, str) and vol.startswith("./"):
                src = vol.split(":")[0]
                src_path = (project_dir / src).resolve()
                if not src_path.exists():
                    errors.append(
                        f"Service '{svc_name}': bind-mount source "
                        f"'{src}' does not exist. Create it before "
                        f"starting the lab to avoid root-owned directories."
                    )
    return errors


def _validate_env_secrets(raw_env: dict[str, str]) -> "LabResult | None":
    """Refuse to start when sensitive .env values are still placeholders.

    Returns a failed :class:`LabResult` ready to bubble out of
    :func:`orchestrate_lab_start`, or ``None`` if every sensitive var
    looks real. Kept separate from the orchestrator so the rule has a
    single test seam and the orchestrator stays a sequence of
    short-circuiting checks.
    """
    placeholders = find_placeholder_env_values(raw_env)
    if not placeholders:
        return None
    msg = (
        "Refusing to start lab: .env values for "
        f"{', '.join(placeholders)} are still set to .env.example "
        "placeholders. Replace them with real secrets before "
        "starting the lab — the SOC stack would otherwise come up "
        "with admin API keys anyone can read in the repo."
    )
    log.error(msg)
    return LabResult(success=False, error=msg)


@dataclass
class _LabStartContext:
    """Mutable scratchpad threaded through the lab-start steps.

    Each step reads inputs it needs from this struct and writes back
    any outputs subsequent steps depend on. Keeps step signatures
    uniform (``ctx -> LabResult | None``) so the orchestrator stays a
    flat list of dispatches.
    """

    project_dir: Path
    skip_seed: bool
    raw_env: dict[str, str] = field(default_factory=dict)
    env: "EnvVars | None" = None
    config: "AptlConfig | None" = None
    backend: "DeploymentBackend | None" = None
    ssh_key_path: Path | None = None


def _step_load_env(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 1: Loading environment variables...")
    env_path = ctx.project_dir / ".env"
    try:
        ctx.raw_env = load_dotenv(env_path)
        ctx.env = env_vars_from_dict(ctx.raw_env)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Failed to load .env: %s", exc)
        return LabResult(success=False, error=f"Failed to load .env: {exc}")
    return _validate_env_secrets(ctx.raw_env)


def _step_load_config(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 2: Loading configuration...")
    config_path = find_config(ctx.project_dir)
    if config_path is None:
        log.error("No aptl.json found in %s", ctx.project_dir)
        return LabResult(
            success=False,
            error=f"Config file aptl.json not found in {ctx.project_dir}",
        )
    try:
        ctx.config = load_config(config_path)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Failed to load config: %s", exc)
        return LabResult(success=False, error=f"Failed to load config: {exc}")
    ctx.backend = _get_backend(ctx.project_dir, ctx.config)
    return None


def _step_ensure_ssh_keys(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 3: Generating SSH keys...")
    keys_dir = ctx.project_dir / "keys"
    host_ssh_dir = Path.home() / ".ssh"
    ssh_result = ensure_ssh_keys(keys_dir=keys_dir, host_ssh_dir=host_ssh_dir)
    if not ssh_result.success:
        log.error("SSH key generation failed: %s", ssh_result.error)
        return LabResult(
            success=False,
            error=f"SSH key generation failed: {ssh_result.error}",
        )
    ctx.ssh_key_path = ssh_result.key_path or (
        Path.home() / ".ssh" / "aptl_lab_key"
    )
    return None


def _step_check_sysreqs(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 4: Checking system requirements...")
    sysreq_result = check_max_map_count()
    if sysreq_result.passed:
        return None
    log.error(
        "vm.max_map_count too low (%d < %d). "
        "Run: sudo sysctl -w vm.max_map_count=262144",
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


def _step_sync_credentials(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 5: Syncing configuration credentials...")
    assert ctx.env is not None  # _step_load_env populated this
    dashboard_config = (
        ctx.project_dir / "config" / "wazuh_dashboard" / "wazuh.yml"
    )
    if dashboard_config.exists():
        try:
            sync_dashboard_config(dashboard_config, ctx.env.api_password)
        except Exception as exc:  # noqa: BLE001 - non-fatal sync warning
            log.warning("Failed to sync dashboard config: %s", exc)
    else:
        log.warning("Dashboard config not found at %s", dashboard_config)

    manager_config = (
        ctx.project_dir / "config" / "wazuh_cluster" / "wazuh_manager.conf"
    )
    if manager_config.exists():
        try:
            sync_manager_config(manager_config, ctx.env.wazuh_cluster_key)
        except Exception as exc:  # noqa: BLE001 - non-fatal sync warning
            log.warning("Failed to sync manager config: %s", exc)
    else:
        log.warning("Manager config not found at %s", manager_config)
    return None


def _step_generate_certs(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 6: Generating SSL certificates...")
    cert_result = ensure_ssl_certs(ctx.project_dir)
    if cert_result.success:
        return None
    log.error("Certificate generation failed: %s", cert_result.error)
    return LabResult(
        success=False,
        error=f"Certificate generation failed: {cert_result.error}",
    )


def _step_check_bind_mounts(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 6b: Checking bind-mount sources...")
    mount_errors = _check_bind_mounts(ctx.project_dir)
    if not mount_errors:
        return None
    for err in mount_errors:
        log.error("Bind-mount issue: %s", err)
    return LabResult(
        success=False,
        error="Bind-mount pre-flight failed:\n" + "\n".join(mount_errors),
    )


def _step_pull_images(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 7: Pre-pulling container images...")
    assert ctx.backend is not None
    images = [
        f"wazuh/wazuh-manager:{WAZUH_IMAGE_VERSION}",
        f"wazuh/wazuh-indexer:{WAZUH_IMAGE_VERSION}",
        f"wazuh/wazuh-dashboard:{WAZUH_IMAGE_VERSION}",
    ]
    for warning in ctx.backend.pull_images(images):
        log.warning(warning)
    return None


def _step_start_containers(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 8: Starting containers...")
    assert ctx.config is not None and ctx.backend is not None
    start_result = start_lab(
        ctx.config, project_dir=ctx.project_dir, backend=ctx.backend
    )
    if not start_result.success and ctx.config.containers.soc:
        log.warning(
            "Initial compose up failed (SOC dependencies may still be "
            "initializing). Waiting 60s and retrying..."
        )
        import time
        time.sleep(60)
        start_result = start_lab(
            ctx.config, project_dir=ctx.project_dir, backend=ctx.backend
        )
    if start_result.success:
        return None
    log.error("Lab start failed: %s", start_result.error)
    return LabResult(
        success=False,
        error=f"Lab start failed: {start_result.error}",
    )


def _step_wait_for_services(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 9: Waiting for services...")
    assert ctx.config is not None and ctx.env is not None
    if not ctx.config.containers.wazuh:
        return None

    indexer_result = wait_for_service(
        check_fn=partial(
            check_indexer_ready,
            url="https://localhost:9200",
            username=ctx.env.indexer_username,
            password=ctx.env.indexer_password,
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
            container_name="aptl-wazuh-manager",
        ),
        timeout=120,
        interval=5,
        service_name="Wazuh Manager API",
    )
    if not manager_result.ready:
        log.warning("Manager API may still be initializing")
    return None


def _step_test_ssh(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 10: Testing SSH connectivity...")
    assert ctx.config is not None and ctx.ssh_key_path is not None
    ssh_tests: list[tuple[str, int, str]] = []
    if ctx.config.containers.victim:
        ssh_tests.append(("victim", 2022, "labadmin"))
    if ctx.config.containers.kali:
        ssh_tests.append(("kali", 2023, "kali"))
    if ctx.config.containers.reverse:
        ssh_tests.append(("reverse", 2027, "labadmin"))

    for name, port, user in ssh_tests:
        ssh_wait = wait_for_service(
            check_fn=partial(
                test_ssh_connection,
                host="localhost",
                port=port,
                user=user,
                key_path=ctx.ssh_key_path,
            ),
            timeout=60,
            interval=5,
            service_name=f"SSH ({name})",
        )
        if ssh_wait.ready:
            log.info("SSH to %s is ready", name)
        else:
            log.warning(
                "SSH to %s not ready after %ds",
                name, int(ssh_wait.elapsed_seconds),
            )
    return None


def _step_capture_snapshot(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 11: Capturing range snapshot...")
    snapshot = capture_snapshot(config_dir=ctx.project_dir, backend=ctx.backend)
    log.info(
        "Range: %d containers, %d networks, %d services, %d SSH endpoints",
        len(snapshot.containers),
        len(snapshot.networks),
        len(snapshot.services),
        len(snapshot.ssh),
    )
    return None


def _step_build_mcps(ctx: _LabStartContext) -> LabResult | None:
    log.info("Step 12: Building MCP servers...")
    mcp_script = ctx.project_dir / "mcp" / "build-all-mcps.sh"
    if not mcp_script.exists():
        log.warning("MCP build script not found at %s", mcp_script)
        return None
    try:
        mcp_result = subprocess.run(
            [str(mcp_script)],
            capture_output=True,
            text=True,
            cwd=ctx.project_dir,
        )
        if mcp_result.returncode != 0:
            log.warning("MCP build had errors: %s", mcp_result.stderr)
        else:
            log.info("MCP servers built successfully")
    except (FileNotFoundError, OSError) as exc:
        log.warning("Failed to build MCP servers: %s", exc)
    return None


def _step_seed_soc(ctx: _LabStartContext) -> LabResult | None:
    if ctx.skip_seed:
        log.info("Step 13: Skipping SOC seeding (--skip-seed)")
        return None
    log.info("Step 13: Seeding SOC tools...")
    assert ctx.config is not None
    seed_script = ctx.project_dir / "scripts" / "seed-prime.sh"
    if not seed_script.exists():
        log.debug("SOC seed script not found at %s", seed_script)
        return None
    if not ctx.config.containers.soc:
        log.debug("SOC profile not enabled, skipping seed")
        return None
    try:
        seed_result = subprocess.run(
            [str(seed_script)],
            capture_output=True,
            text=True,
            cwd=ctx.project_dir,
            timeout=1200,
        )
        if seed_result.returncode != 0:
            log.warning("SOC seeding had errors: %s", seed_result.stderr)
        else:
            log.info("SOC tools seeded successfully")
    except subprocess.TimeoutExpired:
        log.warning("SOC seeding timed out (non-fatal)")
    except (FileNotFoundError, OSError) as exc:
        log.warning("Failed to seed SOC tools: %s", exc)
    return None


def _step_sync_mcp_config(ctx: _LabStartContext) -> LabResult | None:
    # `.mcp.json` is the canonical config Claude Code, Cursor, and Cline
    # read to spawn MCP servers. Seed-prime writes API keys (TheHive
    # provisioned, MISP/Shuffle defaults) to `.env`. If the user has a
    # local `.mcp.json`, surface those keys into per-server env blocks
    # so the MCPs authenticate without manual rewiring after a fresh
    # `lab stop -v` + `lab start`.
    log.info("Step 14: Syncing MCP client config with seeded API keys...")
    try:
        _sync_mcp_config_keys(ctx.project_dir)
    except Exception as exc:  # pragma: no cover - non-fatal
        log.warning("MCP config sync skipped: %s", exc)
    return None


# Ordered list of steps the orchestrator dispatches. Keep numbered
# comments in sync with the step bodies above so log lines and source
# stay aligned.
_LAB_START_STEPS = (
    _step_load_env,
    _step_load_config,
    _step_ensure_ssh_keys,
    _step_check_sysreqs,
    _step_sync_credentials,
    _step_generate_certs,
    _step_check_bind_mounts,
    _step_pull_images,
    _step_start_containers,
    _step_wait_for_services,
    _step_test_ssh,
    _step_capture_snapshot,
    _step_build_mcps,
    _step_seed_soc,
    _step_sync_mcp_config,
)


def orchestrate_lab_start(
    project_dir: Path,
    skip_seed: bool = False,
) -> LabResult:
    """Orchestrate the complete lab startup process.

    Steps are individual ``_step_*`` functions executed in order; the
    first one that returns a non-``None`` :class:`LabResult` short-
    circuits the whole run. Each step pulls what it needs out of the
    shared :class:`_LabStartContext` and writes any outputs subsequent
    steps depend on back into it.

    Args:
        project_dir: Root directory of the APTL project.
        skip_seed: If True, skip SOC tool seeding (Step 13).

    Returns:
        LabResult indicating overall success or failure.
    """
    log.info("Starting APTL lab from %s", project_dir)
    ctx = _LabStartContext(project_dir=project_dir, skip_seed=skip_seed)

    for step in _LAB_START_STEPS:
        result = step(ctx)
        if result is not None:
            return result

    log.info("APTL lab started successfully!")
    return LabResult(success=True, message="Lab started successfully")


def _sync_mcp_config_keys(project_dir: Path) -> None:
    """Update `.mcp.json` env entries for dynamic API keys from `.env`.

    Idempotent: runs after seed-prime, only touches the three known dynamic
    server names, only updates keys the seed script defines. If `.mcp.json`
    does not exist (e.g. fresh checkout, user hasn't configured an MCP
    client yet) this is a no-op.
    """
    import json

    mcp_path = project_dir / ".mcp.json"
    env_path = project_dir / ".env"
    if not mcp_path.exists() or not env_path.exists():
        log.debug("MCP sync: missing %s or %s, skipping",
                  mcp_path.name, env_path.name)
        return

    # Use the canonical .env parser so quoted values, `export` prefixes,
    # and trailing comments are handled identically to lab startup.
    try:
        env_vals = load_dotenv(env_path)
    except FileNotFoundError:
        log.debug("MCP sync: %s vanished between checks; skipping",
                  env_path.name)
        return

    # server name -> env keys it expects
    SERVER_KEYS = {
        "aptl-casemgmt": ["THEHIVE_API_KEY"],
        "aptl-threatintel": ["MISP_API_KEY"],
        "aptl-soar": ["SHUFFLE_API_KEY"],
    }

    cfg = json.loads(mcp_path.read_text())
    servers = cfg.get("mcpServers", {})
    updated = []
    for server_name, keys in SERVER_KEYS.items():
        spec = servers.get(server_name)
        if not spec:
            continue
        spec_env = spec.setdefault("env", {})
        for key in keys:
            if key in env_vals and env_vals[key] != spec_env.get(key):
                spec_env[key] = env_vals[key]
                updated.append(f"{server_name}.{key}")

    if updated:
        mcp_path.write_text(json.dumps(cfg, indent=2) + "\n")
        log.info("MCP sync: refreshed %s in %s",
                 ", ".join(updated), mcp_path.name)
    else:
        log.debug("MCP sync: no changes needed")
