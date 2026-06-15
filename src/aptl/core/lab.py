"""Lab lifecycle management.

Wraps deployment backends for starting, stopping, and checking lab status.
Docker interactions go through the DeploymentBackend protocol, with Docker
Compose as the default backend.  Includes the full orchestration of lab
startup.
"""

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
    sync_suricata_misp_rule_baselines,
)
from aptl.core.env import (
    EnvVars,
    env_vars_from_dict,
    find_placeholder_env_values,
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
    check_manager_api_ready,
    test_ssh_connection,
    wait_for_service,
)
from aptl.core.endpoints import select_ssh_host
from aptl.core.snapshot import capture_snapshot, container_networks
from aptl.core.ssh import ensure_pivot_key, ensure_ssh_keys
from aptl.core.sysreqs import check_max_map_count
from aptl.utils.logging import get_logger
from aptl.utils.redaction import redact

if TYPE_CHECKING:
    from docker.client import DockerClient

    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("lab")


def start_aces_scenario(
    project_dir: Path,
    config: AptlConfig,
    backend: "DeploymentBackend",
) -> LabResult:
    """Lazy ACES handoff import for the public lab-start path."""
    try:
        from aptl.backends.aces import start_aces_scenario as _start_aces_scenario
    except ImportError as exc:
        error = f"ACES runtime handoff unavailable: {redact(str(exc))}"
        log.error(error)
        return LabResult(success=False, error=error)

    return _start_aces_scenario(project_dir, config, backend)


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

# All known Docker Compose profiles. Used as fallback when config is
# unavailable (e.g. stop_lab, kill switch).  Keep in sync with
# docker-compose.yml profile definitions.
ALL_KNOWN_PROFILES = [
    "wazuh", "victim", "kali", "reverse",
    "enterprise", "soc", "mail", "fileshare", "dns",
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
    raw_env: dict[str, str] = field(default_factory=dict)
    env: "EnvVars | None" = None
    config: "AptlConfig | None" = None
    backend: "DeploymentBackend | None" = None
    ssh_key_path: Path | None = None
    diagnostics: list[StartupDiagnostic] = field(default_factory=list)


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
_UNUSABLE_IMPACTS = frozenset(
    {DiagnosticImpact.CAPABILITY, DiagnosticImpact.READINESS}
)


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
        ctx.raw_env = load_dotenv(env_path)
        ctx.env = env_vars_from_dict(ctx.raw_env)
    except (FileNotFoundError, ValueError) as exc:
        log.exception("Failed to load .env")
        return LabResult(success=False, error=f"Failed to load .env: {exc}")
    return _validate_env_secrets(ctx.raw_env)


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
    ctx.ssh_key_path = ssh_result.key_path or (
        Path.home() / ".ssh" / "aptl_lab_key"
    )

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
    """Validate host kernel settings required by Wazuh."""
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
        log.error("%s containment violation: %s", label, exc)
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
def _step_sync_suricata_misp_rule_baselines(
    ctx: _LabStartContext,
) -> LabResult | None:
    """Render writable Suricata MISP rule baseline files."""
    log.info("Step 5b: Seeding Suricata MISP rule baselines...")
    from aptl.core.deployment import SSHComposeBackend
    if isinstance(ctx.backend, SSHComposeBackend):
        return LabResult(
            success=False,
            error=(
                "Suricata MISP rule baselines are rendered to .aptl/suricata/ "
                "on the host running `aptl lab start`, but the configured "
                "deployment backend targets a remote Docker daemon, so the "
                "remote bind mounts would not see them. Run `aptl lab start` "
                "on the deployment host instead, or switch deployment.provider "
                "to the local Docker Compose backend."
            ),
        )
    return _run_credential_sync(
        "Suricata MISP rule baselines",
        sync_suricata_misp_rule_baselines,
        ctx.project_dir,
    )


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
                log.error(
                    "SOC certificate generation failed: %s", cert_result.error
                )
                result = LabResult(
                    success=False,
                    error=(
                        "SOC certificate generation failed: "
                        f"{cert_result.error}"
                    ),
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
    start_result = start_aces_scenario(ctx.project_dir, ctx.config, ctx.backend)
    if not start_result.success and ctx.config.containers.soc:
        log.warning(
            "Initial compose up failed (SOC dependencies may still be "
            "initializing). Waiting 60s and retrying..."
        )
        import time
        time.sleep(60)
        start_result = start_aces_scenario(ctx.project_dir, ctx.config, ctx.backend)
    if start_result.success:
        return None
    log.error("Lab start failed: %s", start_result.error)
    return LabResult(
        success=False,
        error=f"Lab start failed: {start_result.error}",
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
        # Indexer is the SIEM store — without it, detections never land.
        # Lab is up but telemetry is degraded.
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
    ssh_tests: list[tuple[str, str]] = []
    if ctx.config.containers.victim:
        ssh_tests.append(("victim", "labadmin"))
    if ctx.config.containers.kali:
        ssh_tests.append(("kali", "kali"))
    if ctx.config.containers.reverse:
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
            message=(
                f"SSH to {name} not ready after "
                f"{int(ssh_wait.elapsed_seconds)}s"
            ),
            operator_action=(
                f"Check the {name} container's sshd; scenarios cannot "
                "drive this target until SSH is reachable"
            ),
        )
    return None


@_runtime_require(
    lambda ctx: backend_is_initialized(ctx.backend),
    description="backend_is_initialized(ctx.backend)",
)
def _step_capture_snapshot(ctx: _LabStartContext) -> LabResult | None:
    """Capture a non-fatal inventory snapshot of the started range."""
    log.info("Step 11: Capturing range snapshot...")
    try:
        snapshot = capture_snapshot(
            config_dir=ctx.project_dir, backend=ctx.backend
        )
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
    log.info(
        "Range: %d containers, %d networks, %d services, %d SSH endpoints",
        len(snapshot.containers),
        len(snapshot.networks),
        len(snapshot.services),
        len(snapshot.ssh),
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
            operator_action=(
                "Verify mcp/build-all-mcps.sh exists in the project tree"
            ),
        )
        return None
    try:
        mcp_result = subprocess.run(
            [str(mcp_script)],
            capture_output=True,
            text=True,
            cwd=ctx.project_dir,
        )
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
                operator_action=(
                    "Inspect mcp/build-all-mcps.sh output in the lab log"
                ),
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
            operator_action=(
                "Inspect mcp/build-all-mcps.sh permissions and tooling"
            ),
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
        log.warning(
            "SOC profile enabled but seed script not found at %s", seed_script
        )
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
        seed_result = subprocess.run(
            [str(seed_script)],
            capture_output=True,
            text=True,
            cwd=ctx.project_dir,
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
            operator_action=(
                "Inspect scripts/seed-prime.sh permissions and tooling"
            ),
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
                "Inspect .mcp.json env blocks against .env after a "
                "fresh lab start"
            ),
        )
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
    _step_sync_suricata_misp_rule_baselines,
    _step_generate_certs,
    _step_generate_soc_certs,
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
                    f"Lab orchestration contract violated at "
                    f"step '{step.__name__}'"
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
    )


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
