"""Lab lifecycle management.

Wraps deployment backends for starting, stopping, and checking lab status.
Docker interactions go through the DeploymentBackend protocol, with Docker
Compose as the default backend.  Includes the full orchestration of lab
startup.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

import icontract
import yaml

from aptl.core.certs import ensure_ssl_certs
from aptl.core.soc_ca import ensure_soc_certs
from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.contracts import (
    backend_is_initialized,
    config_is_loaded,
    env_is_loaded,
    required_profiles_enabled,
    ssh_key_is_ready,
)
from aptl.core.credentials import (
    PathContainmentError,
    sync_dashboard_config,
    sync_manager_config,
)
from aptl.core.suricata_seed import build_suricata_volume_seeds
from aptl.core.env import (
    EnvVars,
    env_vars_from_dict,
    find_placeholder_env_values,
    hydrate_dotenv,
    load_dotenv,
)

# Re-export the lifecycle DTO types from the leaf module (#266 + ADR-030).
# The leaf has no back-edges, so this is a normal top-level import.
from aptl.core.lab_types import (
    DiagnosticImpact as DiagnosticImpact,
    DiagnosticSeverity as DiagnosticSeverity,
    LabResult as LabResult,
    LabStatus as LabStatus,
    StartupDiagnostic as StartupDiagnostic,
    StartupOutcome as StartupOutcome,
)
from aptl.core.services import (
    check_indexer_ready,
    check_indexer_status,
    check_manager_api_ready,
    test_ssh_connection,
    wait_for_service,
)
from aptl.core.endpoints import (
    build_ssh_endpoints,
    select_ssh_host,
    terminal_ssh_endpoints,
)
from aptl.core.host_keys import pin_terminal_host_keys
from aptl.core import hostenv
from aptl.core.snapshot import (
    SSHEndpoint,
    capture_snapshot,
    container_networks,
    list_container_snapshots,
)
from aptl.core.ssh import ensure_pivot_key, ensure_ssh_keys
from aptl.core.sysreqs import check_docker_buildx, check_max_map_count
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from docker.client import DockerClient

    from aptl.backends.aces import AcesStartOutcome
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("lab")

ProgressCallback = Callable[[str], None]

_STALE_NETWORK_RECOVERY_HINT = (
    "Run `aptl lab stop` and retry, or `aptl lab stop -v` if you need a clean lab."
)


def _looks_like_stale_realization_network_error(error: str) -> bool:
    """Return True when Docker reports old APTL networks with stale labels."""

    return (
        "Existing network " in error
        and " does not match realized network " in error
        and "label org.aptl.realization.network expected 'true'" in error
    )


def _lab_start_failure_error(error: str) -> str:
    """Build the CLI-visible lab-start failure message with recovery hints."""

    message = f"Lab start failed: {error}"
    if _looks_like_stale_realization_network_error(error):
        return f"{message}\n{_STALE_NETWORK_RECOVERY_HINT}"
    return message


def start_aces_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
    *,
    run_store: object = None,
    run_id: str | None = None,
) -> AcesStartOutcome | LabResult:
    """Lazy ACES handoff import for the public lab-start path.

    ``run_store``/``run_id`` (resolved once per lab-start run, REP-001 / GAP 4)
    are threaded into the ACES handoff so orchestration persists workflow
    artifacts under the same run directory the run record is written to.
    """
    try:
        from aptl.backends.aces import start_aces_scenario as _start_aces_scenario
    except ImportError as exc:
        error = f"ACES runtime handoff unavailable: {redact(str(exc))}"
        log.error(error)
        return LabResult(success=False, error=error)

    return _start_aces_scenario(
        project_dir,
        config,
        backend,
        scenario_path=scenario_path,
        run_store=run_store,
        run_id=run_id,
    )


def selected_profiles_for_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
    scenario_path: Path | None = None,
) -> set[str]:
    """Lazy ACES import for the scenario's selected Compose profiles.

    Returns the profile set the scenario actually starts, so post-start
    readiness checks scope to it instead of the global config flags. On import
    failure returns an empty set (the readiness steps then skip rather than
    falsely waiting on services).
    """
    try:
        from aptl.backends.aces import (
            selected_profiles_for_scenario as _selected_profiles,
        )

        return set(
            _selected_profiles(
                project_dir, config, backend, scenario_path=scenario_path
            )
        )
    # broad-except: resolving selected profiles is best-effort enrichment for
    # the readiness steps. The lab already started; any failure (import,
    # missing/invalid SDL, ACES planning error) must degrade to an empty set so
    # the readiness steps skip rather than crash the start or falsely wait.
    except Exception as exc:
        log.warning("Could not resolve selected profiles: %s", redact(str(exc)))
        return set()


def _runtime_require(
    condition: Callable[..., bool],
    description: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """`icontract.require` that survives `python -O` AND keeps violation
    messages secret-safe.

    Two production-readiness properties combined into one wrapper:

    1. `icontract.require` defaults `enabled` to `__debug__`, so under
       an optimized interpreter the decorator becomes a no-op and the
       precondition is silently dropped — the exact failure mode the
       `assert` → `icontract` migration in issue #214 was meant to
       close. `enabled=True` pins the guard on unconditionally.

    2. icontract's default `ViolationError` renderer interpolates the
       `repr()` of every bound condition argument. For these contracts
       the bound argument is `_LabStartContext` (or `AptlConfig`), and
       after `_step_load_env` runs the context's `raw_env`/`EnvVars`
       fields hold secrets such as `WAZUH_CLUSTER_KEY` that the existing
       string redactor in `aptl.utils.redaction` does not mask. A
       direct caller (test, future integration code, accidental
       `log.error(exc)`) would surface that repr in plain text — ADR-031
       § Guardrails explicitly forbids that. We force a fixed-template
       message via the `error=` callback so the contract is secret-safe
       at the *source*, not just at the orchestrator edge.
    """

    # icontract introspects the error callable's signature and tries to
    # resolve every named parameter against the condition's bound
    # kwargs. A no-arg factory sidesteps that check entirely: icontract
    # detects `parameters` is empty, skips kwarg resolution, and calls
    # `error()` directly.
    def _narrow_violation() -> icontract.ViolationError:
        """Return a fixed violation without rendering bound arguments."""
        return icontract.ViolationError(description)

    return icontract.require(
        condition,
        description=description,
        enabled=True,
        error=_narrow_violation,
    )


WAZUH_IMAGE_VERSION = "4.12.0"

# Image used to seed Suricata's named volumes at lab start (ADR-043). The
# Suricata service's own image is reused so the seed step adds no new
# supply-chain surface; it is already pulled for the `suricata` service.
# A test pins this to the `suricata` service's `image:` in
# docker-compose.yml so the two cannot drift.
SURICATA_IMAGE = "jasonish/suricata:7.0"

# All known Docker Compose profiles. Used as fallback when config is
# unavailable (e.g. stop_lab, kill switch).  Keep in sync with
# docker-compose.yml profile definitions.
ALL_KNOWN_PROFILES = [
    "wazuh",
    "victim",
    "kali",
    "reverse",
    "enterprise",
    "soc",
    "mail",
    "fileshare",
    "dns",
    "otel",
]


def docker_client() -> "DockerClient":
    """Get a Docker client. Separated for easy mocking."""
    import docker

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


@_runtime_require(
    lambda config: config_is_loaded(config),
    description="config_is_loaded(config)",
)
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


def clean_boot_lab(
    project_dir: Path,
    *,
    remove_volumes: bool = True,
    skip_seed: bool = False,
    scenario_path: Optional[Path] = None,
    backend: Optional["DeploymentBackend"] = None,
    progress: ProgressCallback | None = None,
) -> LabResult:
    """Boot the lab into a guaranteed clean state (RNG-001).

    The single reusable destructive clean-state lifecycle mode: tear down
    the project-scoped deployment removing Compose-managed volumes (the
    first cleanup policy), then boot through the public start path so the
    range comes up free of contamination (files, processes, service
    databases/logs, generated in-container credentials) from a prior run.

    Cleanup and boot reuse :func:`stop_lab` and
    :func:`orchestrate_lab_start`; both are project-scoped through the
    deployment backend (``-p <project_name>`` + compose-project labels),
    so this never enumerates or removes unrelated Docker objects on a
    shared daemon. It removes only Compose-managed state — never ``.env``,
    ``keys/``, ``.mcp.json``, checked-in config, or run archives.

    A failed cleanup is a fatal lifecycle failure, not a partial-readiness
    state: a contaminated environment must never be reused as "clean", so
    a stop failure short-circuits before the boot. Raw Docker stderr is
    redacted before it crosses this boundary.

    Args:
        project_dir: Root directory of the APTL project.
        remove_volumes: Cleanup policy. When ``True`` (default) the
            teardown removes Compose-managed volumes; the knob lets future
            cleanup variations extend this one mode.
        skip_seed: Forwarded to the start path (skip SOC tool seeding).
        scenario_path: Optional selected ACES SDL scenario path.
        backend: Optional pre-created deployment backend, forwarded to the
            teardown so callers that already resolved one avoid a re-create.
        progress: Optional callback for participant-facing startup updates.

    Returns:
        LabResult — the boot outcome on success, or a fatal ``FAILED``
        result carrying the redacted cleanup error when teardown fails.
    """
    if progress is not None:
        progress("Stopping the existing lab before clean boot.")
    stop_result = stop_lab(
        remove_volumes=remove_volumes,
        project_dir=project_dir,
        backend=backend,
    )
    if not stop_result.success:
        return LabResult(
            success=False,
            error=redact(
                f"clean-state cleanup failed; lab not booted: {stop_result.error}"
            ),
            outcome=StartupOutcome.FAILED,
        )

    return orchestrate_lab_start(
        project_dir,
        skip_seed=skip_seed,
        scenario_path=scenario_path,
        progress=progress,
    )


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


def lab_terminal_ssh_endpoints(
    project_dir: Path,
    backend: Optional["DeploymentBackend"] = None,
) -> dict[str, SSHEndpoint]:
    """Resolve the running lab's terminal SSH endpoints (ADR-040).

    Projects ``ENDPOINT_REGISTRY`` over live container inventory so the
    WebSocket relay derives each target's host/user/port from the
    canonical boundary (container IP over the bridge, issue #293) instead
    of a hardcoded ``localhost`` map. Keyed by terminal short-name
    (``victim`` / ``kali`` / ``reverse`` / ``workstation``).
    """
    if backend is None:
        backend = _get_backend(project_dir)
    return terminal_ssh_endpoints(list_container_snapshots(backend))


def _check_bind_mounts(
    project_dir: Path,
    enabled_profiles: list[str] | None = None,
) -> list[str]:
    """Check that bind-mount source paths exist as files, not root-owned dirs.

    Parses docker-compose.yml for relative bind mounts (``./`` prefix) and
    verifies that each source path exists. Returns a list of error messages
    for any missing sources so the caller can fail early instead of letting
    Docker silently create root-owned directories.

    Profile-aware (SEC-006 / ADR-034 § Guardrails): only services whose
    Compose profile is enabled by the current ``aptl.json`` are checked.
    A service with ``profiles: ["soc"]`` whose bind-mount source lives
    under a generated, gitignored directory (e.g. ``config/soc_certs/``,
    rendered only by ``_step_generate_soc_certs`` when SOC is enabled)
    would otherwise fail this preflight on a non-SOC lab start, even
    though the service is never started. ``enabled_profiles=None`` keeps
    the original "check every service" behaviour for direct callers.
    """
    compose_path = project_dir / "docker-compose.yml"
    if not compose_path.exists():
        log.debug("No docker-compose.yml found, skipping bind-mount check")
        return []

    try:
        data = yaml.safe_load(compose_path.read_text())
    except yaml.YAMLError as e:
        return [f"Failed to parse docker-compose.yml: {e}"]

    active = set(enabled_profiles) if enabled_profiles is not None else None
    services = data.get("services", {}) if isinstance(data, dict) else {}
    errors: list[str] = []
    for svc_name, svc_def in services.items():
        errors.extend(
            _check_service_bind_mounts(svc_name, svc_def, project_dir, active)
        )
    return errors


def _check_service_bind_mounts(
    svc_name: str,
    svc_def: object,
    project_dir: Path,
    active_profiles: set[str] | None,
) -> list[str]:
    """Return bind-mount errors for one Compose service.

    Extracted from :func:`_check_bind_mounts` so the parent stays inside
    the cognitive-complexity budget. Handles the profile-filter gating
    (``profiles:`` with no overlap → skip) and the per-volume relative
    path check.
    """
    if not isinstance(svc_def, dict):
        return []
    if active_profiles is not None:
        svc_profiles = svc_def.get("profiles") or []
        # A service with no `profiles:` key runs unconditionally;
        # a service with profiles only runs when at least one is active.
        if svc_profiles and not (set(svc_profiles) & active_profiles):
            return []
    errors: list[str] = []
    for vol in svc_def.get("volumes", []):
        if not isinstance(vol, str) or not vol.startswith("./"):
            continue
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
class _LabStartContext(object):
    """Mutable scratchpad threaded through the lab-start steps.

    Each step reads inputs it needs from this struct and writes back
    any outputs subsequent steps depend on. Keeps step signatures
    uniform (``ctx -> LabResult | None``) so the orchestrator stays a
    flat list of dispatches.

    ``diagnostics`` collects structured partial-readiness notes (ADR-030)
    emitted by individual steps. The orchestrator turns the final list
    into a :class:`StartupOutcome` via :func:`derive_startup_outcome`.
    """

    project_dir: Path
    skip_seed: bool
    scenario_path: Path | None = None
    progress: ProgressCallback | None = None
    raw_env: dict[str, str] = field(default_factory=dict)
    env: "EnvVars | None" = None
    config: "AptlConfig | None" = None
    backend: "DeploymentBackend | None" = None
    ssh_key_path: Path | None = None
    selected_profiles: set[str] = field(default_factory=set)
    # Published host ports after conflict resolution (host_ports.ResolvedPort),
    # so the access summary can report the real port each service landed on.
    resolved_ports: list[object] = field(default_factory=list)
    diagnostics: list[StartupDiagnostic] = field(default_factory=list)
    # REP-001: ACES start outcome and range snapshot for run record writing.
    # Use object to avoid circular imports; typed at use sites.
    aces_outcome: object = None
    snapshot: object = None
    # REP-001 / GAP 4: one run store + run_id resolved once per lab-start run,
    # threaded through orchestration and reused by the run-record step so
    # workflow artifacts and the record share a single run directory.
    run_store: object = None
    run_id: str | None = None


# Log format string for structured diagnostics. Kept module-level so
# ``_emit_diagnostic``'s three log branches (error / warning / info) share
# a single literal — extracting silences Sonar ``python:S1192`` and keeps
# any future format tweak in one place.
_DIAGNOSTIC_LOG_FORMAT = "[%s|%s] %s"


# Severities that contribute to a "degraded" outcome. ``info`` is
# intentionally excluded — it is a structured note, not a degradation.
_DEGRADING_SEVERITIES = frozenset(
    {DiagnosticSeverity.WARNING, DiagnosticSeverity.ERROR}
)

# Impacts that drag the outcome to DEGRADED_UNUSABLE rather than
# DEGRADED_USABLE. Lab is partially up but the named capability/SSH
# reach is missing for the operator's intended use.
_UNUSABLE_IMPACTS = frozenset({DiagnosticImpact.CAPABILITY, DiagnosticImpact.READINESS})


def derive_startup_outcome(
    diagnostics: list[StartupDiagnostic],
    fatal: bool,
) -> StartupOutcome:
    """Map a diagnostics list (plus a fatal short-circuit flag) to an outcome.

    Rule (ADR-030):

    - ``fatal=True`` always wins → ``FAILED`` (a hard stop must be
      distinguishable from any degraded state).
    - Any degrading-severity diagnostic with ``impact`` in
      ``{capability, readiness}`` → ``DEGRADED_UNUSABLE``.
    - Any degrading-severity diagnostic with ``impact`` in
      ``{cosmetic, telemetry}`` → ``DEGRADED_USABLE``.
    - Otherwise → ``READY``.

    Pure function; safe to call from tests directly.
    """
    outcome = StartupOutcome.READY
    if fatal:
        outcome = StartupOutcome.FAILED
        return outcome
    has_unusable = False
    has_degrading = False
    for diag in diagnostics:
        if diag.severity not in _DEGRADING_SEVERITIES:
            continue
        has_degrading = True
        if diag.impact in _UNUSABLE_IMPACTS:
            has_unusable = True
            # Already the worst non-fatal bucket.
            break
    if has_unusable:
        outcome = StartupOutcome.DEGRADED_UNUSABLE
    elif has_degrading:
        outcome = StartupOutcome.DEGRADED_USABLE
    return outcome


def _emit_diagnostic(
    ctx: _LabStartContext,
    *,
    step: str,
    impact: DiagnosticImpact,
    severity: DiagnosticSeverity,
    message: str,
    component: str = "",
    operator_action: str = "",
) -> None:
    """Append a structured diagnostic to the context and log it.

    Centralizes the ADR-030 redaction-shape rule. Callers pass narrow
    labels; this helper additionally runs ``aptl.utils.redaction.redact()``
    over the free-form fields (``message``, ``component``,
    ``operator_action``) so a future caller that accidentally interpolates
    an exception payload, env value, or subprocess stderr cannot leak it
    through the single choke point that feeds CLI, API, and web. The
    structured ``step`` identifier is an internal literal and is not
    redacted (redaction there would defeat attribution).
    """
    safe_message = redact(message)
    safe_component = redact(component)
    safe_operator_action = redact(operator_action)
    diag = StartupDiagnostic(
        step=step,
        impact=impact,
        severity=severity,
        message=safe_message,
        component=safe_component,
        operator_action=safe_operator_action,
    )
    ctx.diagnostics.append(diag)
    label = f"{step}/{safe_component}" if safe_component else step
    if severity is DiagnosticSeverity.ERROR:
        log.error(_DIAGNOSTIC_LOG_FORMAT, impact.value, label, safe_message)
    elif severity is DiagnosticSeverity.WARNING:
        log.warning(_DIAGNOSTIC_LOG_FORMAT, impact.value, label, safe_message)
    else:
        log.info(_DIAGNOSTIC_LOG_FORMAT, impact.value, label, safe_message)


def _step_load_env(ctx: _LabStartContext) -> LabResult | None:
    """Load and validate environment values for lab startup."""
    log.info("Step 1: Loading environment variables...")
    env_path = ctx.project_dir / ".env"
    try:
        hydration = hydrate_dotenv(env_path)
        if hydration.changed:
            action = "created" if hydration.created else "updated"
            log.info(
                "%s .env with %d hydrated credential values",
                action.capitalize(),
                len(hydration.updated_keys),
            )
        ctx.raw_env = load_dotenv(env_path)
        ctx.env = env_vars_from_dict(ctx.raw_env)
    except (OSError, ValueError) as exc:
        log.exception("Failed to load .env")
        return LabResult(success=False, error=f"Failed to load .env: {exc}")
    return _validate_env_secrets(ctx.raw_env)


def _step_resolve_host_ports(ctx: _LabStartContext) -> LabResult | None:
    """Remap any published host port that is already in use before Compose runs.

    Docker Compose aborts the whole ``up`` if it cannot bind a requested host
    port, and on Windows/macOS other software routinely holds ports the lab
    wants (mDNS on 5353, an editor's port-forwarding, etc.). This probes each
    published port and, for any that are taken, exports a free alternate through
    the ``${VAR:-default}`` indirection Compose reads from the environment — so
    startup succeeds and the access summary can report the real port. Ports the
    operator pinned in ``.env`` / the environment are honoured as-is; Linux
    hosts with nothing on the defaults see no change.
    """
    from aptl.core import host_ports

    ctx.resolved_ports = host_ports.resolve_host_ports(
        ctx.project_dir, reserved_env=set(ctx.raw_env)
    )
    for resolved in ctx.resolved_ports:
        if resolved.remapped:
            _emit_progress(
                ctx,
                f"Host port {resolved.default_port} for {resolved.service} is "
                f"in use; publishing on {resolved.resolved_port} instead.",
            )
    return None


def _step_load_config(ctx: _LabStartContext) -> LabResult | None:
    """Load aptl.json and initialize the configured deployment backend."""
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
        log.exception("Failed to load config")
        return LabResult(success=False, error=f"Failed to load config: {exc}")
    ctx.backend = _get_backend(ctx.project_dir, ctx.config)
    return None


def _step_ensure_ssh_keys(ctx: _LabStartContext) -> LabResult | None:
    """Ensure the host-side lab SSH key exists."""
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
    ctx.ssh_key_path = ssh_result.key_path or (Path.home() / ".ssh" / "aptl_lab_key")

    # SEC #417: the kali pivot key is scenario content (kali -> targets),
    # separate from the control-plane key above. Generated into a gitignored
    # dir and bind-mounted (private -> kali, public -> targets).
    pivot_result = ensure_pivot_key(pivot_dir=ctx.project_dir / "config" / "lab-ssh")
    if not pivot_result.success:
        log.error("Pivot key generation failed: %s", pivot_result.error)
        return LabResult(
            success=False,
            error=f"Pivot key generation failed: {pivot_result.error}",
        )
    return None


def _step_check_sysreqs(ctx: _LabStartContext) -> LabResult | None:
    """Validate host requirements before Compose starts building images."""
    log.info("Step 4: Checking system requirements...")
    sysreq_result = check_max_map_count()
    if not sysreq_result.passed:
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

    buildx_result = check_docker_buildx()
    if buildx_result.passed:
        return None
    log.error("Docker Buildx unavailable: %s", buildx_result.error)
    return LabResult(
        success=False,
        error=(
            "Docker Buildx is required to build the APTL lab images "
            f"({buildx_result.command} failed: {buildx_result.error}). "
            f"{buildx_result.install_hint}"
        ),
    )


def _run_credential_sync(
    label: str,
    fn: Callable[..., object],
    *args: object,
) -> LabResult | None:
    """Render one credentialized config file; any failure aborts lab start.

    The rendered file is a mandatory Docker Compose bind-mount source
    (ADR-028) — if it is not produced fresh this run, the lab would come
    up with stale or absent credential config — so a render failure is
    always fatal. ``PathContainmentError`` is surfaced as a security
    guardrail breach; anything else (missing template, disk error,
    permission error, …) is surfaced as a generic render failure. Either
    way the orchestrator stops with a failed ``LabResult``; ``None``
    means the render succeeded and orchestration continues.
    """
    try:
        fn(*args)
    except PathContainmentError as exc:
        log.exception("%s containment violation", label)
        return LabResult(success=False, error=f"{label}: {exc}")
    except Exception as exc:
        log.exception("Failed to render %s", label.lower())
        return LabResult(
            success=False, error=f"Failed to render {label.lower()}: {exc}"
        )
    return None


@_runtime_require(
    lambda ctx: env_is_loaded(ctx.env),
    description="env_is_loaded(ctx.env)",
)
@_runtime_require(
    lambda ctx: backend_is_initialized(ctx.backend),
    description="backend_is_initialized(ctx.backend)",
)
def _step_sync_credentials(ctx: _LabStartContext) -> LabResult | None:
    """Render credentialized service configuration files."""
    log.info("Step 5: Rendering credentialized service config...")
    # Contract above is the runtime guard; this assert is a typing hint.
    assert ctx.env is not None
    # The rendered files (.aptl/config/...) are Docker bind-mount sources
    # resolved on the *daemon's* filesystem. With the SSH-remote backend
    # the daemon is on another host, so rendering locally would leave the
    # remote bind mounts pointing at nothing (or at a stale copy) — and
    # `_check_bind_mounts` only inspects the local tree, so preflight
    # would pass and compose would then fail. Rather than silently ship a
    # broken (or placeholder-credentialled) remote lab, refuse: the
    # render must run on the deployment host (e.g. `aptl lab start` over
    # SSH on that host). Routing generated-artifact materialization
    # through the deployment backend is the proper fix and is tracked
    # separately. See ADR-028 § Non-Goals.
    from aptl.core.deployment import SSHComposeBackend

    if isinstance(ctx.backend, SSHComposeBackend):
        return LabResult(
            success=False,
            error=(
                "Credentialized service config is rendered to .aptl/config/ "
                "on the host running `aptl lab start`, but the configured "
                "deployment backend targets a remote Docker daemon, so the "
                "remote bind mounts would not see it. Run `aptl lab start` on "
                "the deployment host instead, or switch deployment.provider "
                "to the local Docker Compose backend."
            ),
        )
    # Both writers own their canonical project-relative source-template
    # and rendered-output paths and validate containment internally; the
    # orchestrator only passes the trusted project root. See ADR-028
    # (runtime-rendered service config) and ADR-007 (security guardrail).
    # Any render failure — containment breach or otherwise — aborts lab
    # start because the rendered files are mandatory Compose mount
    # sources; on success they are guaranteed freshly written this run.
    result = _run_credential_sync(
        "Dashboard config",
        sync_dashboard_config,
        ctx.project_dir,
        ctx.env.api_password,
    )
    if result is not None:
        return result
    return _run_credential_sync(
        "Manager config",
        sync_manager_config,
        ctx.project_dir,
        ctx.env.wazuh_cluster_key,
    )


@_runtime_require(
    lambda ctx: backend_is_initialized(ctx.backend),
    description="backend_is_initialized(ctx.backend)",
)
def _step_seed_suricata_volumes(
    ctx: _LabStartContext,
) -> LabResult | None:
    """Seed Suricata config + MISP rules into Compose named volumes (ADR-043).

    Replaces the former ``.aptl/`` host render: nothing checked-in is
    bind-mounted onto a path the Suricata image entrypoint chowns, so host
    ownership is never rewritten. A root seed container copies the
    checked-in baselines into project-scoped named volumes and retires the
    legacy UID-991-owned ``.aptl/suricata/rules/misp`` bind dir.
    """
    log.info("Step 5b: Seeding Suricata runtime volumes...")
    from aptl.core.deployment import SSHComposeBackend

    if isinstance(ctx.backend, SSHComposeBackend):
        return LabResult(
            success=False,
            error=(
                "Suricata runtime volumes are seeded from checked-in source "
                "on the host running `aptl lab start`, but the configured "
                "deployment backend targets a remote Docker daemon, so the "
                "host source would not be visible to it. Run `aptl lab start` "
                "on the deployment host instead, or switch deployment.provider "
                "to the local Docker Compose backend."
            ),
        )
    # runtime guard above
    assert ctx.backend is not None
    return _seed_suricata_volumes_local(ctx)


def _seed_suricata_volumes_local(ctx: _LabStartContext) -> LabResult | None:
    """Restore checked-in source ownership and seed the Suricata named volumes.

    Split out of :func:`_step_seed_suricata_volumes` (which retains the
    remote-backend guard) so each function stays within the project's
    return-count and complexity limits. ``ctx.backend`` is the local
    Compose backend, asserted non-``None`` by the caller.
    """
    from aptl.core.suricata_seed import ensure_suricata_config_source_ownership
    from aptl.core.deployment.errors import (
        BackendSeedError,
        BackendTimeoutError,
    )

    # ctx.backend is narrowed to the local Compose backend by the caller's guard.
    assert ctx.backend is not None
    # Pull the seeder image up front. Both the ownership repair and the seed
    # container implicitly pull it via `docker run`, and on a fresh host a
    # failed/slow implicit pull can surface as an opaque `exit 125` from the
    # seeder with no docker stderr in the redacted log path — pulling here
    # keeps registry failures at a stage the user can reason about (a
    # `Failed to pull ...` warning) instead of a bare seed-exit code.
    for pull_warning in ctx.backend.pull_images([SURICATA_IMAGE]):
        log.warning(pull_warning)
    ownership = ensure_suricata_config_source_ownership(ctx.project_dir, SURICATA_IMAGE)
    if not ownership.success:
        log.error(
            "Suricata config source ownership restore failed: %s",
            ownership.error,
        )
        return LabResult(
            success=False,
            error=(
                f"Suricata config source ownership restore failed: {ownership.error}"
            ),
        )
    try:
        seeds = build_suricata_volume_seeds(ctx.project_dir)
        ctx.backend.seed_named_volumes(seeds, seeder_image=SURICATA_IMAGE)
    except (
        PathContainmentError,
        BackendSeedError,
        BackendTimeoutError,
        # ``OSError`` subsumes ``FileNotFoundError`` / ``NotADirectoryError``.
        OSError,
    ) as exc:
        # Narrow, redacted failure (ADR-043): name the artifact/exception
        # type, not raw Docker stderr.
        log.exception("Suricata volume seed failed: %s", type(exc).__name__)
        return LabResult(
            success=False,
            error=f"Suricata runtime volume seeding failed: {exc}",
        )
    return None


def _step_generate_certs(ctx: _LabStartContext) -> LabResult | None:
    """Generate SSL certificates required by the base stack."""
    log.info("Step 6: Generating SSL certificates...")
    cert_result = ensure_ssl_certs(ctx.project_dir)
    if cert_result.success:
        return None
    log.error("Certificate generation failed: %s", cert_result.error)
    return LabResult(
        success=False,
        error=f"Certificate generation failed: {cert_result.error}",
    )


@_runtime_require(
    lambda ctx: config_is_loaded(ctx.config),
    description="config_is_loaded(ctx.config)",
)
@_runtime_require(
    lambda ctx: backend_is_initialized(ctx.backend),
    description="backend_is_initialized(ctx.backend)",
)
def _step_generate_soc_certs(ctx: _LabStartContext) -> LabResult | None:
    """Step 6c: materialize the SOC stack lab CA + per-service certs.

    Returns ``None`` on success (including the SOC-disabled no-op path)
    so the orchestrator continues to the next step. Returns a failed
    :class:`LabResult` when (a) the configured backend is remote (the
    generated tree lives on the *controlling* host and would not be
    visible across the SSH boundary — same shape as
    ``_step_sync_credentials`` / ADR-028) or (b) the in-process
    cryptography generation itself failed.
    """
    log.info("Step 6c: Generating SOC stack lab CA + service certs...")
    # runtime guard above; this assert is for the type-checker.
    assert ctx.config is not None
    result: LabResult | None = None
    if not ctx.config.containers.soc:
        log.debug("SOC profile not enabled, skipping SOC CA generation")
    else:
        # Generated artifacts land under config/soc_certs/ on the host running
        # `aptl lab start`. With the SSH-remote backend the Docker daemon is
        # on another host whose bind mounts cannot see them — same shape as
        # `_step_sync_credentials` (ADR-028).
        from aptl.core.deployment import SSHComposeBackend

        if isinstance(ctx.backend, SSHComposeBackend):
            result = LabResult(
                success=False,
                error=(
                    "SOC stack lab CA is generated under config/soc_certs/ on "
                    "the host running `aptl lab start`, but the configured "
                    "deployment backend targets a remote Docker daemon, so the "
                    "remote bind mounts would not see it. Run `aptl lab start` "
                    "on the deployment host instead, or switch "
                    "deployment.provider to the local Docker Compose backend."
                ),
            )
        else:
            cert_result = ensure_soc_certs(ctx.project_dir)
            if not cert_result.success:
                log.error("SOC certificate generation failed: %s", cert_result.error)
                result = LabResult(
                    success=False,
                    error=(f"SOC certificate generation failed: {cert_result.error}"),
                )
    return result


def _step_check_bind_mounts(ctx: _LabStartContext) -> LabResult | None:
    """Validate active Compose bind-mount sources before Docker runs."""
    log.info("Step 6b: Checking bind-mount sources...")
    enabled = (
        ctx.config.containers.enabled_profiles() if ctx.config is not None else None
    )
    mount_errors = _check_bind_mounts(ctx.project_dir, enabled_profiles=enabled)
    if not mount_errors:
        return None
    for err in mount_errors:
        log.error("Bind-mount issue: %s", err)
    return LabResult(
        success=False,
        error="Bind-mount pre-flight failed:\n" + "\n".join(mount_errors),
    )


@_runtime_require(
    lambda ctx: backend_is_initialized(ctx.backend),
    description="backend_is_initialized(ctx.backend)",
)
def _step_pull_images(ctx: _LabStartContext) -> LabResult | None:
    """Pre-pull high-latency images before Compose startup."""
    log.info("Step 7: Pre-pulling container images...")
    # Contract above is the runtime guard.
    assert ctx.backend is not None
    images = [
        f"wazuh/wazuh-manager:{WAZUH_IMAGE_VERSION}",
        f"wazuh/wazuh-indexer:{WAZUH_IMAGE_VERSION}",
        f"wazuh/wazuh-dashboard:{WAZUH_IMAGE_VERSION}",
    ]
    warnings = list(ctx.backend.pull_images(images))
    for warning in warnings:
        # Backend already includes stderr in the log line; existing
        # log-redaction boundary owns scrubbing it.
        log.warning(warning)
    if warnings:
        # Pre-pull is a latency optimization — Compose pulls on demand
        # when containers start. Surface as a cosmetic info diagnostic
        # so automation sees the count without scraping the log.
        _emit_diagnostic(
            ctx,
            step="pull_images",
            impact=DiagnosticImpact.COSMETIC,
            severity=DiagnosticSeverity.INFO,
            message=(
                f"Pre-pull failed for {len(warnings)} image(s); compose "
                "will pull on demand"
            ),
            operator_action="No action required; first lab use may be slower",
        )
    return None


_WAZUH_MANAGER_CONTAINER = "aptl-wazuh-manager"


def _wazuh_manager_daemon_count(ctx: _LabStartContext) -> int | None:
    """Return the number of live ``wazuh-*`` daemons in the manager container.

    Returns ``None`` when the count can't be determined — the container is not
    running, or the inspect/exec probe failed. Best-effort: it swallows every
    inspect/exec failure so a diagnostics probe can never abort lab start.
    """
    assert ctx.backend is not None
    # Amazon Linux 2023 in the manager image ships without `ps`, so walk
    # /proc directly to count the live wazuh-* daemons.
    probe = ["sh", "-c",
             "ls /proc/[0-9]*/comm 2>/dev/null | while read f; do "
             "read n < \"$f\"; case \"$n\" in wazuh-*) echo \"$n\";; esac; "
             "done | sort -u | wc -l"]
    try:
        info = ctx.backend.container_inspect(_WAZUH_MANAGER_CONTAINER)
        if (info.get("State") or {}).get("Status") != "running":
            return None
        result = ctx.backend.container_exec(
            _WAZUH_MANAGER_CONTAINER, probe, timeout=10
        )
        return (
            int((result.stdout or "0").strip())
            if result.returncode == 0
            else None
        )
    except Exception:
        # Deliberately broad: this watchdog must never let an inspect/exec
        # failure abort lab start (covered by the swallow-exceptions tests).
        return None


def _restart_wazuh_manager_if_stuck(ctx: _LabStartContext) -> None:
    """Restart wazuh-manager if it is Up but its daemons never spawned (#732).

    Colima on macOS reproducibly gets s6-supervise into a state where
    every attempt to exec the (executable) `run` scripts returns EACCES
    and the wazuh daemons never spawn. The container itself stays Up
    because PID 1 (s6-svscan) survives, so docker's own restart policy
    never fires. A single `docker restart` clears the state cleanly.

    This helper is best-effort: any failure to inspect or restart is
    logged and ignored (the caller retries the compose up regardless).
    """
    # Caller (`_step_start_containers`) is icontract-guarded so
    # `ctx.backend is not None` — no defensive check needed here.
    assert ctx.backend is not None
    count = _wazuh_manager_daemon_count(ctx)
    # Daemons are alive, or their state could not be determined: nothing to do.
    if count is None or count > 0:
        return
    log.warning(
        "wazuh-manager is Up but has 0 wazuh-* daemons; restarting once "
        "before compose retry (see issue #732)."
    )
    try:
        ctx.backend.container_restart(_WAZUH_MANAGER_CONTAINER)
    except Exception as exc:
        # Deliberately broad: a failed restart attempt must not abort start.
        log.warning("wazuh-manager restart attempt failed: %s", exc)


@_runtime_require(
    lambda ctx: config_is_loaded(ctx.config),
    description="config_is_loaded(ctx.config)",
)
@_runtime_require(
    lambda ctx: backend_is_initialized(ctx.backend),
    description="backend_is_initialized(ctx.backend)",
)
def _step_start_containers(ctx: _LabStartContext) -> LabResult | None:
    """Start the selected lab profiles through the ACES handoff."""
    log.info("Step 8: Starting containers...")
    # Runtime guards above.
    assert ctx.config is not None and ctx.backend is not None
    # GAP 4: resolve the single run target ONCE, before the ACES handoff, so
    # orchestration persists workflow artifacts and the later run-record step
    # write to the same run directory / run_id.
    ctx.run_store, ctx.run_id = _resolve_run_target(ctx)
    outcome = start_aces_scenario(
        ctx.project_dir,
        ctx.config,
        ctx.backend,
        scenario_path=ctx.scenario_path,
        run_store=ctx.run_store,
        run_id=ctx.run_id,
    )
    lab_result = outcome.lab_result if hasattr(outcome, "lab_result") else outcome
    if not lab_result.success and ctx.config.containers.soc:
        log.warning(
            "Initial compose up failed (SOC dependencies may still be "
            "initializing). Waiting 60s and retrying..."
        )
        import time

        time.sleep(60)
        # Colima on macOS reproducibly leaves the wazuh-manager container
        # in a state where s6-supervise reports EACCES on the (executable)
        # `run` scripts and the wazuh daemons never spawn (#732). The
        # container stays Up so docker's own restart policy never fires,
        # but no wazuh-* processes exist inside. A single `docker restart`
        # clears the state; do that before the retry so compose isn't
        # forced to try running `up` against a broken container instance.
        _restart_wazuh_manager_if_stuck(ctx)
        outcome = start_aces_scenario(
            ctx.project_dir,
            ctx.config,
            ctx.backend,
            scenario_path=ctx.scenario_path,
            run_store=ctx.run_store,
            run_id=ctx.run_id,
        )
        lab_result = outcome.lab_result if hasattr(outcome, "lab_result") else outcome
    if lab_result.success:
        # Store the ACES start outcome for the run record step (REP-001).
        ctx.aces_outcome = outcome
        # Scope the post-start readiness checks to the profiles this scenario
        # actually started, not the global config flags. A curated bounded
        # scenario starts a subset, so a config-flag gate would wait on (and
        # fail) services it never launched.
        ctx.selected_profiles = selected_profiles_for_scenario(
            ctx.project_dir,
            ctx.config,
            ctx.backend,
            scenario_path=ctx.scenario_path,
        )
        return None
    log.error("Lab start failed: %s", lab_result.error)
    return LabResult(
        success=False,
        error=_lab_start_failure_error(lab_result.error),
    )


@_runtime_require(
    lambda ctx: config_is_loaded(ctx.config),
    description="config_is_loaded(ctx.config)",
)
@_runtime_require(
    lambda ctx: env_is_loaded(ctx.env),
    description="env_is_loaded(ctx.env)",
)
def _step_wait_for_services(ctx: _LabStartContext) -> LabResult | None:
    """Wait for Wazuh services and emit degraded-readiness diagnostics."""
    log.info("Step 9: Waiting for services...")
    # Runtime guards above.
    assert ctx.config is not None and ctx.env is not None
    # Gate on the profiles the scenario actually started, not the config flag:
    # a bounded scenario may omit Wazuh even when the container is enabled.
    if "wazuh" not in ctx.selected_profiles:
        return None

    # Use the actual published host port for the indexer. If port 9200 was
    # already in use on the host (Cursor / another OpenSearch / a k8s
    # port-forward), `_step_resolve_host_ports` remapped the publish; probing
    # the literal 9200 in that case reaches whatever else is on 9200 and
    # falsely reports the indexer as unready. `ctx.resolved_ports` carries
    # the post-remap answer.
    indexer_port = next(
        (
            r.resolved_port
            for r in ctx.resolved_ports
            if getattr(r, "service", None) == "wazuh.indexer"
        ),
        9200,
    )
    indexer_url = f"https://localhost:{indexer_port}"
    indexer_result = wait_for_service(
        check_fn=partial(
            check_indexer_ready,
            url=indexer_url,
            username=ctx.env.indexer_username,
            password=ctx.env.indexer_password,
        ),
        # Generous cold-boot headroom: OpenSearch's first-boot init (cluster
        # formation + security index) can run long when the whole SOC stack and
        # MCP builds start at once.
        timeout=600,
        interval=10,
        service_name="Wazuh Indexer",
        progress=ctx.progress,
    )
    if not indexer_result.ready:
        # Indexer is the SIEM store — without it, detections never land.
        # Lab is up but telemetry is degraded. A second, one-shot
        # classification probe tells apart "still not listening" from
        # "listening but rejecting the configured credentials" (#623) —
        # the latter means the persisted indexer volume's admin password
        # no longer matches .env, which is a distinct, actionable state.
        final_status = check_indexer_status(
            url=indexer_url,
            username=ctx.env.indexer_username,
            password=ctx.env.indexer_password,
        )
        if final_status in (401, 403):
            _emit_diagnostic(
                ctx,
                step="wait_for_services",
                component="wazuh_indexer",
                impact=DiagnosticImpact.TELEMETRY,
                severity=DiagnosticSeverity.WARNING,
                message=(
                    f"Wazuh Indexer rejected the configured INDEXER_PASSWORD "
                    f"(HTTP {final_status}) while its listener was responding"
                ),
                operator_action=(
                    "The persisted wazuh-indexer-data volume likely still holds a "
                    "previous admin password, so the changed .env credentials no "
                    "longer match. Run `aptl lab stop -v` then `aptl lab start` to "
                    "reset the indexer security state, or restore the original "
                    "INDEXER_PASSWORD in .env."
                ),
            )
        else:
            _emit_diagnostic(
                ctx,
                step="wait_for_services",
                component="wazuh_indexer",
                impact=DiagnosticImpact.TELEMETRY,
                severity=DiagnosticSeverity.WARNING,
                message=(
                    "Wazuh Indexer did not become ready within "
                    f"{int(indexer_result.elapsed_seconds)}s"
                ),
                operator_action=(
                    "Check indexer container logs; SIEM ingest will not work "
                    "until indexer is healthy"
                ),
            )

    manager_result = wait_for_service(
        check_fn=partial(
            check_manager_api_ready,
            container_name="aptl-wazuh-manager",
        ),
        timeout=120,
        interval=5,
        service_name="Wazuh Manager API",
        progress=ctx.progress,
    )
    if not manager_result.ready:
        _emit_diagnostic(
            ctx,
            step="wait_for_services",
            component="wazuh_manager",
            impact=DiagnosticImpact.TELEMETRY,
            severity=DiagnosticSeverity.WARNING,
            message=(
                "Wazuh Manager API did not become ready within "
                f"{int(manager_result.elapsed_seconds)}s"
            ),
            operator_action=(
                "Check manager container logs; agents will not report "
                "until manager API is healthy"
            ),
        )
    return None


@_runtime_require(
    lambda ctx: config_is_loaded(ctx.config),
    description="config_is_loaded(ctx.config)",
)
@_runtime_require(
    lambda ctx: ssh_key_is_ready(ctx.ssh_key_path),
    description="ssh_key_is_ready(ctx.ssh_key_path)",
)
def _step_test_ssh(ctx: _LabStartContext) -> LabResult | None:
    """Probe SSH reachability for enabled interactive lab targets."""
    log.info("Step 10: Testing SSH connectivity...")
    # config / ssh_key guarded by the decorators above; backend is set
    # by the earlier compose-up step and is a structural invariant here.
    assert (
        ctx.config is not None
        and ctx.ssh_key_path is not None
        and ctx.backend is not None
    )
    if _docker_vm_hides_bridge_ips():
        log.info(
            "Skipping host SSH probes: Docker VM mode does not expose "
            "Compose bridge IPs to the host"
        )
        return None
    # Probe only the interactive targets the scenario actually started. Gating
    # on the selected profiles (not config flags) keeps a bounded scenario from
    # warning about targets it intentionally omitted.
    ssh_tests: list[tuple[str, str]] = []
    if "victim" in ctx.selected_profiles:
        ssh_tests.append(("victim", "labadmin"))
    if "kali" in ctx.selected_profiles:
        ssh_tests.append(("kali", "kali"))
    if "reverse" in ctx.selected_profiles:
        ssh_tests.append(("reverse", "labadmin"))

    for name, user in ssh_tests:
        # Lab targets sit on internal-only networks with no published
        # host port (issue #293), so a `localhost:<port>` probe never
        # connects. Address sshd by container IP — the host reaches it
        # over the bridge — on the container-side port 22 directly.
        host = select_ssh_host(container_networks(ctx.backend, f"aptl-{name}"))
        if host is None:
            _emit_diagnostic(
                ctx,
                step="test_ssh",
                component=f"ssh:{name}",
                impact=DiagnosticImpact.READINESS,
                severity=DiagnosticSeverity.WARNING,
                message=f"{name} container has no resolvable network IP",
                operator_action=(
                    f"Check that the aptl-{name} container is running and "
                    "attached to a lab network"
                ),
            )
            continue
        ssh_wait = wait_for_service(
            check_fn=partial(
                test_ssh_connection,
                host=host,
                port=22,
                user=user,
                key_path=ctx.ssh_key_path,
            ),
            timeout=60,
            interval=5,
            service_name=f"SSH ({name})",
            progress=ctx.progress,
        )
        if ssh_wait.ready:
            log.info("SSH to %s is ready", name)
            continue
        # SSH to a target is the control plane scenarios drive — without
        # it, that target is effectively unreachable for red/blue work.
        _emit_diagnostic(
            ctx,
            step="test_ssh",
            component=f"ssh:{name}",
            impact=DiagnosticImpact.READINESS,
            severity=DiagnosticSeverity.WARNING,
            message=(f"SSH to {name} not ready after {int(ssh_wait.elapsed_seconds)}s"),
            operator_action=(
                f"Check the {name} container's sshd; scenarios cannot "
                "drive this target until SSH is reachable"
            ),
        )
    return None


def _docker_vm_hides_bridge_ips() -> bool:
    """Return True when host-side probes cannot route to container IPs."""
    return hostenv.docker_mode() in {
        hostenv.DOCKER_DESKTOP,
        hostenv.DOCKER_VM,
    }


@_runtime_require(
    lambda ctx: backend_is_initialized(ctx.backend),
    description="backend_is_initialized(ctx.backend)",
)
def _step_capture_snapshot(ctx: _LabStartContext) -> LabResult | None:
    """Capture a non-fatal inventory snapshot of the started range."""
    log.info("Step 11: Capturing range snapshot...")
    try:
        snapshot = capture_snapshot(config_dir=ctx.project_dir, backend=ctx.backend)
    except Exception:
        # Snapshot is the run-archive inventory; its loss is observability
        # debt, not a hard failure (ADR-030). Keep exception detail in
        # the log only; diagnostic is narrow.
        log.exception("Range snapshot capture failed")
        _emit_diagnostic(
            ctx,
            step="capture_snapshot",
            impact=DiagnosticImpact.TELEMETRY,
            severity=DiagnosticSeverity.WARNING,
            message="Range snapshot capture failed; run inventory will be incomplete",
            operator_action=(
                "Inspect lab logs; re-run `aptl lab status -j` to capture "
                "inventory manually once the deployment backend is reachable"
            ),
        )
        return None
    # Store snapshot for run record step (REP-001).
    ctx.snapshot = snapshot
    log.info(
        "Range: %d containers, %d networks, %d services, %d SSH endpoints",
        len(snapshot.containers),
        len(snapshot.networks),
        len(snapshot.services),
        len(snapshot.ssh),
    )
    return None


def _step_write_run_record(ctx: _LabStartContext) -> LabResult | None:
    """Write an ACES-aligned reproducibility record into the run archive (REP-001).

    Non-fatal: a failure to write the record emits a WARNING diagnostic but
    does not abort the lab start. The lab is already running at this point.
    """
    log.info("Step 11c: Writing run reproducibility record...")
    if ctx.aces_outcome is None or ctx.snapshot is None:
        log.warning(
            "REP-001: Skipping run record — ACES outcome or range snapshot unavailable"
        )
        return None
    try:
        _write_run_record(ctx)
    except Exception:
        log.exception("REP-001: Run record write failed (non-fatal)")
        _emit_diagnostic(
            ctx,
            step="write_run_record",
            impact=DiagnosticImpact.TELEMETRY,
            severity=DiagnosticSeverity.WARNING,
            message="Run reproducibility record could not be written; run archive will lack REP-001 record",
            operator_action=(
                "Inspect lab logs; the lab is running but the run archive "
                "will be missing its reproducibility record"
            ),
        )
    return None


def _resolve_run_target(ctx: _LabStartContext) -> tuple[object, str]:
    """Resolve the single (run_store, run_id) for this lab-start run (GAP 4).

    Prefers the active scenario's trace-scoped run dir (``resolve_active_run_dir``)
    so MCP-side and lab-side artifacts share one directory; otherwise mints a
    filesystem-safe ``run_<UTC timestamp>`` id under the default run store base
    dir. The minted id is shaped to pass ``runstore._validate_id``. Resolved
    once and cached on ctx so orchestration and the run record agree.
    """
    from datetime import datetime, timezone

    from aptl.core.runstore import LocalRunStore, resolve_active_run_dir

    state_dir = ctx.project_dir / ".aptl"
    active_run_dir = resolve_active_run_dir(state_dir)
    if active_run_dir is not None:
        return LocalRunStore(active_run_dir.parent), active_run_dir.name
    run_id = datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ")
    return LocalRunStore(state_dir / "runs"), run_id


def _resolve_aces_snapshot(outcome: object) -> object:
    """Return a valid RuntimeSnapshot from the ACES outcome, or a blank default."""
    from aces_contracts.runtime_state import RuntimeSnapshot as _RuntimeSnapshot

    final_snapshot = getattr(outcome, "final_snapshot", None)
    if final_snapshot is None or not isinstance(final_snapshot, _RuntimeSnapshot):
        return _RuntimeSnapshot()
    return final_snapshot


def _assemble_container_image_digests(snapshot: object) -> dict[str, str]:
    """Build the container-name → image-digest mapping from a RangeSnapshot."""
    return {
        c.name: c.image_digest
        for c in snapshot.containers  # type: ignore[attr-defined]
        if c.image_digest
    }


def _assemble_tool_versions(snapshot: object) -> dict[str, str]:
    """Build the tool-name → version mapping from a RangeSnapshot.software."""
    sw = snapshot.software  # type: ignore[attr-defined]
    return {
        k: v
        for k, v in (
            ("python", sw.python_version),
            ("docker", sw.docker_version),
            ("compose", sw.compose_version),
            ("aptl", sw.aptl_version),
            ("aces_sdl", sw.aces_sdl_version),
        )
        if v
    }


def _safe_dict(value: object) -> dict[str, Any]:
    """Return value if it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def _safe_list(value: object) -> list[str]:
    """Return list(value) if value is truthy, else an empty list."""
    return list(value) if value else []  # type: ignore[arg-type]


def _scenario_display_name(scenario_path: Path | None) -> str:
    """Return the scenario file name, or 'unknown' when path is absent."""
    return str(scenario_path.name) if scenario_path else "unknown"


def _write_run_record(ctx: _LabStartContext) -> None:
    """Internal helper: build and persist the reproducibility record."""
    from datetime import datetime, timezone

    from aptl.backends.aces_repro import RunRecordInputs, build_reproducibility_record
    from aptl.core.snapshot import RangeSnapshot, detection_content_digest

    outcome = ctx.aces_outcome
    snapshot = ctx.snapshot
    if not isinstance(snapshot, RangeSnapshot):
        log.warning("REP-001: ctx.snapshot is not a RangeSnapshot; skipping")
        return

    # GAP 4: reuse the run target resolved in _step_start_containers so the
    # record and orchestration artifacts share one run_id; fall back to a
    # fresh resolution only if the start step did not run (defensive).
    if ctx.run_store is not None and ctx.run_id:
        store: object = ctx.run_store
        run_id = ctx.run_id
    else:
        store, run_id = _resolve_run_target(ctx)

    store.create_run(run_id)

    final_snapshot = _resolve_aces_snapshot(outcome)
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    inputs = RunRecordInputs(
        run_id=run_id,
        backend_name="aptl",
        started_at=snapshot.timestamp,
        finished_at=now_str,
        outcome="success",
        final_snapshot=final_snapshot,
        realization_details=_safe_dict(getattr(outcome, "realization_details", {})),
        selected_profiles=_safe_list(getattr(outcome, "selected_profiles", [])),
        scenario_path=getattr(outcome, "scenario_path", None),
        scenario_display_name=_scenario_display_name(
            getattr(outcome, "scenario_path", None)
        ),
        range_snapshot_dict=snapshot.to_dict(),
        config_digests=snapshot.config_hashes,
        container_image_digests=_assemble_container_image_digests(snapshot),
        detection_content_digest=detection_content_digest(ctx.project_dir),
        tool_versions=_assemble_tool_versions(snapshot),
        evidence_references=_collect_evidence_references(store, run_id),
    )
    record = build_reproducibility_record(inputs)
    store.write_json(run_id, "manifest.json", record)
    log.info("REP-001: Run record written to run archive (run_id=%s)", run_id)


# Evidence artifact subtrees scanned for the REP-001 record (GAP 3). Each
# existing file under these directories is referenced by its relative path;
# bytes are never inlined into the record.
_EVIDENCE_KINDS = ("orchestration", "mcp-side", "kali-side")


def _collect_evidence_references(store: object, run_id: str) -> list[dict[str, str]]:
    """Enumerate evidence artifacts that EXIST under the run dir (GAP 3).

    References are RELATIVE to the run directory (never absolute) and the
    manifest never inlines file bytes. On a bare lab start this may be just
    orchestration artifacts (or empty), which is fine.
    """
    try:
        run_dir = store.get_run_path(run_id)
    except Exception:
        return []
    references: list[dict[str, str]] = []
    for kind in _EVIDENCE_KINDS:
        subtree = run_dir / kind
        if not subtree.is_dir():
            continue
        for path in sorted(subtree.rglob("*")):
            if path.is_file():
                references.append(
                    {
                        "path": path.relative_to(run_dir).as_posix(),
                        "kind": kind,
                    }
                )
    return references


def _step_pin_terminal_host_keys(ctx: _LabStartContext) -> LabResult | None:
    """Pin lab SSH host keys for the operator terminal relay (ADR-040).

    Captures each reachable SSH endpoint's server host key (trust-on-
    first-use is permitted only here, during provisioning on the trusted
    host) and writes the ``.aptl/known_hosts`` file the WebSocket relay
    later verifies against. Non-fatal: an endpoint that cannot be pinned
    (not running, not yet reachable) simply makes the relay fail closed
    for that container until the next lab start, so a pinning hiccup must
    not abort an otherwise-healthy lab.
    """
    log.info("Step 11b: Pinning terminal SSH host keys...")
    if ctx.backend is None or ctx.ssh_key_path is None:
        log.debug("Skipping host-key pinning: backend or ssh key unavailable")
    elif _docker_vm_hides_bridge_ips():
        log.info(
            "Skipping host-key pinning: Docker VM mode does not expose "
            "Compose bridge IPs to the host"
        )
    else:
        try:
            endpoints = build_ssh_endpoints(list_container_snapshots(ctx.backend))
            result = pin_terminal_host_keys(
                ctx.project_dir, endpoints, ctx.ssh_key_path
            )
        # Observability only: pinning failures are never fatal to lab start.
        except Exception as exc:  # noqa: BLE001
            log.warning("Terminal SSH host-key pinning failed: %s", exc)
        else:
            if result.failed:
                log.warning(
                    "Terminal SSH host keys not pinned for: %s",
                    ", ".join(result.failed),
                )
    return None


def _step_build_mcps(ctx: _LabStartContext) -> LabResult | None:
    """Build local MCP server artifacts after the lab is running."""
    log.info("Step 12: Building MCP servers...")
    mcp_script = ctx.project_dir / "mcp" / "build-all-mcps.sh"
    if not mcp_script.exists():
        log.warning("MCP build script not found at %s", mcp_script)
        _emit_diagnostic(
            ctx,
            step="build_mcps",
            impact=DiagnosticImpact.CAPABILITY,
            severity=DiagnosticSeverity.WARNING,
            message="MCP build script not found; MCP servers will not be available",
            operator_action=("Verify mcp/build-all-mcps.sh exists in the project tree"),
        )
        return None
    try:
        from aptl.utils.shell import run_shell_script

        mcp_result = run_shell_script(mcp_script, cwd=ctx.project_dir)
        if mcp_result.returncode != 0:
            # Raw stderr stays in the log (existing redaction owns it);
            # the structured diagnostic carries only a narrow summary.
            log.warning("MCP build had errors: %s", mcp_result.stderr)
            _emit_diagnostic(
                ctx,
                step="build_mcps",
                impact=DiagnosticImpact.CAPABILITY,
                severity=DiagnosticSeverity.WARNING,
                message="MCP build returned non-zero exit; see lab logs",
                operator_action=("Inspect mcp/build-all-mcps.sh output in the lab log"),
            )
        else:
            log.info("MCP servers built successfully")
    except (FileNotFoundError, OSError) as exc:
        log.warning("Failed to build MCP servers: %s", exc)
        _emit_diagnostic(
            ctx,
            step="build_mcps",
            impact=DiagnosticImpact.CAPABILITY,
            severity=DiagnosticSeverity.WARNING,
            message="MCP build could not run; see lab logs",
            operator_action=("Inspect mcp/build-all-mcps.sh permissions and tooling"),
        )
    return None


# Issue #214: the prime scenario seed (`scripts/seed-prime.sh`) provisions
# TheHive cases, MISP feeds, and Shuffle workflows that span the full
# prime profile set. ADR-005 supports selective SOC labs (e.g. SOC + Wazuh
# without fileshare), so a missing prime profile must NOT fatally refuse
# lab startup — it just means the prime seed cannot meaningfully run, and
# the lab should come up with SOC empty plus a CAPABILITY diagnostic.
# Kept module-level so the reusable `required_profiles_enabled` predicate
# from `aptl.core.contracts` has a stable constant to read, and so a
# future operation (e.g. an explicit `aptl scenario prime start`
# entrypoint) can wire the same set into a hard `_runtime_require` at
# *that* boundary without redefining it.
_PRIME_REQUIRED_PROFILES = frozenset(
    {"wazuh", "enterprise", "victim", "kali", "fileshare", "soc"}
)

_SEED_SOC_RERUN_ACTION = (
    "Re-run scripts/seed-prime.sh manually once SOC containers are healthy"
)


@_runtime_require(
    lambda ctx: config_is_loaded(ctx.config),
    description="config_is_loaded(ctx.config)",
)
def _step_seed_soc(ctx: _LabStartContext) -> LabResult | None:
    """Seed SOC tools when the configured profile set can support it."""
    if ctx.skip_seed:
        log.info("Step 13: Skipping SOC seeding (--skip-seed)")
    else:
        log.info("Step 13: Seeding SOC tools...")
        # Runtime guard above.
        assert ctx.config is not None
        if not ctx.config.containers.soc:
            log.debug("SOC profile not enabled, skipping seed")
        elif not required_profiles_enabled(ctx.config, _PRIME_REQUIRED_PROFILES):
            _emit_missing_prime_profiles(ctx)
        else:
            _run_seed_soc_script(ctx)
    return None


def _emit_missing_prime_profiles(ctx: _LabStartContext) -> None:
    """Emit the non-fatal diagnostic for partial prime profile sets."""
    assert ctx.config is not None
    missing = sorted(
        _PRIME_REQUIRED_PROFILES - set(ctx.config.containers.enabled_profiles())
    )
    _emit_diagnostic(
        ctx,
        step="seed_soc",
        impact=DiagnosticImpact.CAPABILITY,
        severity=DiagnosticSeverity.WARNING,
        message=(
            "Prime SOC seed needs the full prime profile set; "
            f"missing: {', '.join(missing)}. SOC tools will start empty."
        ),
        operator_action=(
            "Enable the missing prime profiles in aptl.json and "
            "re-run `aptl lab start`, or run `scripts/seed-prime.sh` "
            "manually once the prime stack is up."
        ),
    )


def _run_seed_soc_script(ctx: _LabStartContext) -> None:
    """Run ``seed-prime.sh`` and convert soft failures to diagnostics."""
    seed_script = ctx.project_dir / "scripts" / "seed-prime.sh"
    if not seed_script.exists():
        log.warning("SOC profile enabled but seed script not found at %s", seed_script)
        _emit_diagnostic(
            ctx,
            step="seed_soc",
            impact=DiagnosticImpact.CAPABILITY,
            severity=DiagnosticSeverity.WARNING,
            message=(
                "SOC profile enabled but seed-prime.sh not found; "
                "SOC tools will start empty"
            ),
            operator_action=(
                "Restore scripts/seed-prime.sh and re-run it once SOC "
                "containers are healthy"
            ),
        )
    else:
        _execute_seed_soc_script(ctx, seed_script)


def _execute_seed_soc_script(ctx: _LabStartContext, seed_script: Path) -> None:
    """Execute the SOC seed script and emit non-fatal diagnostics."""
    try:
        from aptl.utils.shell import run_shell_script

        seed_result = run_shell_script(
            seed_script,
            cwd=ctx.project_dir,
            env={**os.environ, **ctx.raw_env},
            timeout=1200,
        )
        if seed_result.returncode != 0:
            log.warning("SOC seeding had errors: %s", seed_result.stderr)
            _emit_diagnostic(
                ctx,
                step="seed_soc",
                impact=DiagnosticImpact.CAPABILITY,
                severity=DiagnosticSeverity.WARNING,
                message="SOC seeding returned non-zero exit; see lab logs",
                operator_action=_SEED_SOC_RERUN_ACTION,
            )
        else:
            log.info("SOC tools seeded successfully")
    except subprocess.TimeoutExpired:
        log.warning("SOC seeding timed out (non-fatal)")
        _emit_diagnostic(
            ctx,
            step="seed_soc",
            impact=DiagnosticImpact.CAPABILITY,
            severity=DiagnosticSeverity.WARNING,
            message="SOC seeding timed out; SOC tools will start empty",
            operator_action=_SEED_SOC_RERUN_ACTION,
        )
    except (FileNotFoundError, OSError) as exc:
        log.warning("Failed to seed SOC tools: %s", exc)
        _emit_diagnostic(
            ctx,
            step="seed_soc",
            impact=DiagnosticImpact.CAPABILITY,
            severity=DiagnosticSeverity.WARNING,
            message="SOC seeding could not run; see lab logs",
            operator_action=("Inspect scripts/seed-prime.sh permissions and tooling"),
        )


def _step_sync_mcp_config(ctx: _LabStartContext) -> LabResult | None:
    """Refresh local MCP client env keys after SOC seeding."""
    # `.mcp.json` is the canonical config Claude Code, Cursor, and Cline
    # read to spawn MCP servers. Seed-prime writes API keys (TheHive
    # provisioned, MISP/Shuffle defaults) to `.env`. If the user has a
    # local `.mcp.json`, surface those keys into per-server env blocks
    # so the MCPs authenticate without manual rewiring after a fresh
    # `lab stop -v` + `lab start`.
    log.info("Step 14: Syncing MCP client config with seeded API keys...")
    try:
        _sync_mcp_config_keys(ctx.project_dir)
    except Exception:
        # Exception text may include API key names — keep it in the log
        # only (existing redaction). Diagnostic stays narrow.
        log.exception("MCP config sync skipped")
        _emit_diagnostic(
            ctx,
            step="mcp_config_sync",
            impact=DiagnosticImpact.CAPABILITY,
            severity=DiagnosticSeverity.WARNING,
            message=(
                "MCP client config not refreshed; MCP servers may not "
                "authenticate without manual key wiring"
            ),
            operator_action=(
                "Inspect .mcp.json env blocks against .env after a fresh lab start"
            ),
        )
    return None


# Ordered list of steps the orchestrator dispatches. Keep numbered
# comments in sync with the step bodies above so log lines and source
# stay aligned.
_LAB_START_STEPS = (
    _step_load_env,
    _step_resolve_host_ports,
    _step_load_config,
    _step_ensure_ssh_keys,
    _step_check_sysreqs,
    _step_sync_credentials,
    _step_seed_suricata_volumes,
    _step_generate_certs,
    _step_generate_soc_certs,
    _step_check_bind_mounts,
    _step_pull_images,
    _step_start_containers,
    _step_wait_for_services,
    _step_test_ssh,
    _step_capture_snapshot,
    _step_write_run_record,
    _step_pin_terminal_host_keys,
    _step_build_mcps,
    _step_seed_soc,
    _step_sync_mcp_config,
)

_LAB_START_PROGRESS_MESSAGES = {
    "_step_load_env": "Preparing environment and credentials.",
    "_step_resolve_host_ports": "Checking host port availability.",
    "_step_load_config": "Loading lab configuration.",
    "_step_ensure_ssh_keys": "Preparing SSH keys.",
    "_step_check_sysreqs": "Checking host requirements.",
    "_step_sync_credentials": "Rendering service configuration.",
    "_step_seed_suricata_volumes": "Preparing Suricata runtime volumes.",
    "_step_generate_certs": "Preparing Wazuh Indexer certificates.",
    "_step_generate_soc_certs": "Preparing SOC TLS certificates.",
    "_step_check_bind_mounts": "Checking bind-mount sources.",
    "_step_pull_images": "Pre-pulling high-latency SOC images.",
    "_step_start_containers": (
        "Starting containers with Docker Compose. First startup can take "
        "several minutes while images build."
    ),
    "_step_wait_for_services": "Waiting for Wazuh services to become ready.",
    "_step_test_ssh": "Testing SSH reachability.",
    "_step_capture_snapshot": "Capturing a range snapshot.",
    "_step_write_run_record": "Writing the run reproducibility record.",
    "_step_pin_terminal_host_keys": "Pinning terminal SSH host keys.",
    "_step_build_mcps": "Building local MCP server artifacts.",
    "_step_seed_soc": "Seeding SOC tools.",
    "_step_sync_mcp_config": "Refreshing MCP client configuration.",
}


def _emit_progress(ctx: _LabStartContext, message: str) -> None:
    """Emit a participant-facing progress update when a caller opted in."""
    if ctx.progress is not None:
        ctx.progress(message)


def orchestrate_lab_start(
    project_dir: Path,
    skip_seed: bool = False,
    scenario_path: Path | None = None,
    progress: ProgressCallback | None = None,
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
        scenario_path: Optional selected ACES SDL scenario path.
        progress: Optional callback for participant-facing startup updates.

    Returns:
        LabResult indicating overall success or failure.
    """
    log.info("Starting APTL lab from %s", project_dir)
    ctx = _LabStartContext(
        project_dir=project_dir,
        skip_seed=skip_seed,
        scenario_path=scenario_path,
        progress=progress,
    )

    for step in _LAB_START_STEPS:
        progress_message = _LAB_START_PROGRESS_MESSAGES.get(step.__name__)
        if progress_message:
            _emit_progress(ctx, progress_message)
        try:
            result = step(ctx)
        except icontract.ViolationError:
            # ADR-031 § Decision: a contract breach inside a step is a
            # fatal state bug. The raw `icontract.ViolationError` string
            # is unsafe to log even after `redact()` — icontract renders
            # bound arguments via `repr()`, which for `_LabStartContext`
            # expands `raw_env` and `EnvVars` (containing e.g.
            # `wazuh_cluster_key`, which `redact()` does not mask).
            # We therefore log only the step name and emit a narrow
            # fatal `LabResult` at the CLI/API edge.
            log.error("Contract violation in step %s", step.__name__)
            return LabResult(
                success=False,
                error=(
                    f"Lab orchestration contract violated at step '{step.__name__}'"
                ),
                outcome=StartupOutcome.FAILED,
                diagnostics=list(ctx.diagnostics),
            )
        if result is not None:
            # Fatal short-circuit. Carry any partial-readiness diagnostics
            # the earlier steps recorded so operators can see what state
            # the lab reached before the failure (ADR-030).
            return LabResult(
                success=False,
                message=result.message,
                error=result.error,
                outcome=StartupOutcome.FAILED,
                diagnostics=list(ctx.diagnostics),
            )

    outcome = derive_startup_outcome(ctx.diagnostics, fatal=False)
    if outcome is StartupOutcome.READY:
        log.info("APTL lab started successfully!")
        message = "Lab started successfully"
    else:
        log.info("APTL lab started with outcome=%s", outcome.value)
        message = f"Lab started with outcome={outcome.value}"
    return LabResult(
        success=True,
        message=message,
        outcome=outcome,
        diagnostics=list(ctx.diagnostics),
        resolved_ports=list(ctx.resolved_ports),
    )


_MCP_SERVER_KEYS = {
    "aptl-casemgmt": ("THEHIVE_API_KEY",),
    "aptl-threatintel": ("MISP_API_KEY",),
    "aptl-soar": ("SHUFFLE_API_KEY",),
}


def _refresh_mcp_server_keys(
    cfg: dict[str, Any], env_vals: dict[str, str]
) -> list[str]:
    """Refresh seeded credentials in MCP server environment blocks."""
    updated: list[str] = []
    servers = cfg.get("mcpServers", {})
    if not isinstance(servers, dict):
        return updated

    for server_name, keys in _MCP_SERVER_KEYS.items():
        spec = servers.get(server_name)
        if not isinstance(spec, dict):
            continue
        spec_env = spec.setdefault("env", {})
        if not isinstance(spec_env, dict):
            continue
        for key in keys:
            if key in env_vals and env_vals[key] != spec_env.get(key):
                spec_env[key] = env_vals[key]
                updated.append(f"{server_name}.{key}")
    return updated


def _sync_mcp_config_keys(project_dir: Path) -> None:
    """Create or update `.mcp.json` with dynamic API keys from `.env`.

    A fresh lab copies the shipped example so its seven enabled custom MCPs
    are client-ready without a manual configuration step. Existing client
    configuration is preserved: only the three known dynamic credential
    entries are refreshed after seed-prime.
    """
    import json

    mcp_path = project_dir / ".mcp.json"
    example_path = project_dir / ".mcp.json.example"
    env_path = project_dir / ".env"
    source_path = mcp_path if mcp_path.exists() else example_path
    if not source_path.exists() or not env_path.exists():
        log.debug(
            "MCP sync: missing client template/config or %s, skipping",
            env_path.name,
        )
        return

    # Use the canonical .env parser so quoted values, `export` prefixes,
    # and trailing comments are handled identically to lab startup.
    try:
        env_vals = load_dotenv(env_path)
    except FileNotFoundError:
        log.debug("MCP sync: %s vanished between checks; skipping", env_path.name)
        return

    cfg = json.loads(source_path.read_text())
    updated = _refresh_mcp_server_keys(cfg, env_vals)

    created = source_path == example_path
    if updated or created:
        mcp_path.write_text(json.dumps(cfg, indent=2) + "\n")
        mcp_path.chmod(0o600)
        action = "created" if created else "refreshed"
        details = f" ({', '.join(updated)})" if updated else ""
        log.info("MCP sync: %s %s%s", action, mcp_path.name, details)
    else:
        log.debug("MCP sync: no changes needed")
