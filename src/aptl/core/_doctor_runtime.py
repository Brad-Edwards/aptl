"""Docker engine checks for ``aptl doctor`` (#1218).

Every daemon probe goes through the configured deployment backend's runner, so
an explicit ``DOCKER_HOST``, context or SSH backend is the engine that
answers. The probes are read-only queries, and a probe's stderr never reaches
a summary or fix.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core import hostenv, sysreqs
from aptl.core.config import AptlConfig
from aptl.core.doctor import (
    _NO_PROJECT_DIRECTORY,
    _PROBE_TIMEOUT_SECONDS,
    CheckStatus,
    DoctorCheck,
    Runner,
    Which,
    _major_minor,
    _skipped,
    _version_text,
)

if TYPE_CHECKING:
    from aptl.core.execution_boundary import BoundaryProbeBackend

# The prerequisites page: "the full `techvault` stack needs more than 20GB".
_FULL_STACK_MEMORY_BYTES = 20 * 10**9
_MIN_COMPOSE_MAJOR = 2
# The checks that need an answering daemon, in report order.
_DAEMON_CHECK_IDS = (
    "rootful-daemon",
    "systemd-substrate",
    "max-map-count",
    "docker-memory",
)
# Every runtime check, in report order; each run reports all of them.
_RUNTIME_CHECK_IDS = (
    "docker-daemon",
    "docker-compose",
    "docker-buildx",
    *_DAEMON_CHECK_IDS,
)
_ENGINE_FIX = "Use Docker Engine 28.0 or newer on a cgroup v2 host (see Prerequisites)."
_USERNS_FIX = (
    "Turn off userns-remap in the Docker daemon configuration (the "
    "`userns-remap` key in daemon.json or the `--userns-remap` dockerd flag) and "
    "restart Docker, or use a rootful daemon without it."
)


def runtime_checks(
    config: AptlConfig, project_root: Path | None, which: Which
) -> list[DoctorCheck]:
    """Check the Docker engine the configured deployment backend would drive.

    ``project_root`` is ``None`` when the project directory does not exist.
    """

    if which("docker") is None:
        return [
            _skipped(check_id, "the Docker CLI is not on PATH (see docker-cli)")
            for check_id in _RUNTIME_CHECK_IDS
        ]
    if project_root is None:
        return _without_backend(
            _skipped("docker-daemon", _NO_PROJECT_DIRECTORY), _NO_PROJECT_DIRECTORY
        )
    return _configured_backend_checks(config, project_root)


def _configured_backend_checks(
    config: AptlConfig, project_root: Path
) -> list[DoctorCheck]:
    """Create the configured backend, as lab start does, and probe through it."""

    from aptl.core.deployment import get_backend

    try:
        backend = get_backend(config, project_root)
    except ValueError:
        # aptl.json loaded, so `aptl config validate` would report it OK; the
        # settings only the backend constructor checks are named instead.
        unavailable = DoctorCheck(
            "docker-daemon",
            CheckStatus.FAILED,
            "The configured deployment backend cannot be created.",
            "Check the deployment settings in aptl.json. The ssh-compose "
            "provider needs ssh_host and ssh_user, an absolute ssh_key path when "
            "one is set, and an ssh_port from 1 to 65535.",
        )
        return _without_backend(
            unavailable,
            "the configured deployment backend cannot be created (see docker-daemon)",
        )
    return _backend_checks(backend)


def _without_backend(daemon: DoctorCheck, reason: str) -> list[DoctorCheck]:
    """Report the runtime checks when no backend runner can be used.

    Buildx is probed on this host, so it still runs. The other checks go
    through the backend's runner, so they are skipped for ``reason``.
    """

    return [
        daemon,
        _skipped("docker-compose", reason),
        _buildx_check(),
        *(_skipped(check_id, reason) for check_id in _DAEMON_CHECK_IDS),
    ]


def _backend_checks(backend: BoundaryProbeBackend) -> list[DoctorCheck]:
    """Probe the selected daemon through the backend's own runner."""

    # The Compose and Buildx plugins belong to the Docker CLI, so they are
    # checked even when the daemon does not answer.
    plugins = [_compose_check(backend._run), _buildx_check()]
    daemon = _daemon_check(backend._run)
    if daemon.status is not CheckStatus.PASSED:
        reason = "the Docker daemon did not answer (see docker-daemon)"
        return [
            daemon,
            *plugins,
            *(_skipped(check_id, reason) for check_id in _DAEMON_CHECK_IDS),
        ]
    rootful = _rootful_check(backend._run)
    return [
        daemon,
        *plugins,
        rootful,
        _substrate_check(backend._run, rootful),
        _max_map_count_check(backend),
        _memory_check(backend._run),
    ]


def _daemon_check(run: Runner) -> DoctorCheck:
    """Ask the selected daemon for its version, without echoing its errors."""

    result = _probe(run, ["docker", "version", "--format", "{{.Server.Version}}"])
    version = _version_text(getattr(result, "stdout", "")) if _ok(result) else None
    if version is not None:
        return DoctorCheck(
            "docker-daemon",
            CheckStatus.PASSED,
            f"Docker Engine {version} answered at the configured endpoint.",
        )
    if "permission denied" in str(getattr(result, "stderr", "") or "").lower():
        return DoctorCheck(
            "docker-daemon",
            CheckStatus.FAILED,
            "This user cannot reach the Docker daemon socket.",
            "Use Docker Desktop, or ask the host administrator for access to the "
            "Docker daemon.",
        )
    return DoctorCheck(
        "docker-daemon",
        CheckStatus.FAILED,
        "The Docker daemon did not answer at the configured endpoint.",
        "Start Docker (Docker Desktop, Colima or the Docker service). If "
        "DOCKER_HOST or a Docker context is set, check that it names the daemon "
        "you want.",
    )


def _rootful_check(run: Runner) -> DoctorCheck:
    """Apply lab start's rootless refusal (#1053) to the selected daemon."""

    from aptl.core.deployment._compose_substrate_gate import require_rootful_daemon
    from aptl.core.deployment.errors import BackendSeedError

    refusal = None
    try:
        require_rootful_daemon(run)
    except BackendSeedError as exc:
        refusal = str(exc)
    if refusal is None:
        return DoctorCheck(
            "rootful-daemon", CheckStatus.PASSED, "The Docker daemon runs rootful."
        )
    return DoctorCheck(
        "rootful-daemon",
        CheckStatus.FAILED,
        _sentence(refusal),
        "Use a rootful Docker daemon, such as Docker Desktop or the default "
        "Docker Engine service.",
    )


def _substrate_check(run: Runner, rootful: DoctorCheck) -> DoctorCheck:
    """Apply the systemd-substrate daemon gate, with the fix for its cause.

    The gate needs cgroup v2, Docker Engine 28.0 or newer, and a daemon
    without userns-remap.
    """

    from aptl.core.deployment._compose_substrate_gate import (
        UnqualifiedDaemonModeError,
        require_substrate_daemon_support,
    )
    from aptl.core.deployment.errors import BackendSeedError

    if rootful.status is not CheckStatus.PASSED:
        return _skipped(
            "systemd-substrate", "the daemon is not rootful (see rootful-daemon)"
        )
    fix = _ENGINE_FIX
    try:
        require_substrate_daemon_support(run)
    except UnqualifiedDaemonModeError as exc:
        refusal, fix = str(exc), _USERNS_FIX
    except BackendSeedError as exc:
        refusal = str(exc)
    else:
        return DoctorCheck(
            "systemd-substrate",
            CheckStatus.PASSED,
            "The daemon runs cgroup v2 with Docker Engine 28.0 or newer.",
        )
    return DoctorCheck(
        "systemd-substrate", CheckStatus.FAILED, _sentence(refusal), fix
    )


def _compose_check(run: Runner) -> DoctorCheck:
    """Check for the Docker Compose v2 plugin lab start drives."""

    result = _probe(run, ["docker", "compose", "version", "--short"])
    version = _major_minor(getattr(result, "stdout", "")) if _ok(result) else None
    if version is not None and version[0] >= _MIN_COMPOSE_MAJOR:
        return DoctorCheck(
            "docker-compose",
            CheckStatus.PASSED,
            f"Docker Compose {version[0]}.{version[1]} is available.",
        )
    return DoctorCheck(
        "docker-compose",
        CheckStatus.FAILED,
        "Docker Compose v2 is not available to the Docker CLI.",
        "Install the Docker Compose v2 plugin. Docker Desktop and the official "
        "Docker Engine installer include it.",
    )


def _buildx_check() -> DoctorCheck:
    """Reuse lab start's Buildx probe, keeping only its install hint."""

    result = sysreqs.check_docker_buildx()
    if result.passed:
        return DoctorCheck(
            "docker-buildx", CheckStatus.PASSED, "Docker Buildx is available."
        )
    return DoctorCheck(
        "docker-buildx",
        CheckStatus.FAILED,
        "Docker Buildx is not available to the Docker CLI; lab images need it.",
        result.install_hint,
    )


def _max_map_count_check(backend: BoundaryProbeBackend) -> DoctorCheck:
    """Apply lab start's vm.max_map_count check to the selected daemon's host."""

    from aptl.core.execution_boundary import observe_execution_boundary

    containment = observe_execution_boundary(backend).host_containment
    mode = sysreqs.docker_mode_for_containment(containment)
    result = sysreqs.check_max_map_count(selected_mode=mode)
    if not result.applicable:
        return _max_map_count_not_read(mode, containment, result.required_value)
    if result.passed:
        return DoctorCheck(
            "max-map-count",
            CheckStatus.PASSED,
            f"vm.max_map_count is {result.current_value}.",
        )
    observed = (
        f"vm.max_map_count is {result.current_value}"
        if result.current_value
        else "vm.max_map_count could not be read"
    )
    return DoctorCheck(
        "max-map-count",
        CheckStatus.FAILED,
        f"{observed}; OpenSearch needs at least {result.required_value}.",
        f"Run {_sysctl_change(result.required_value)}",
    )


def _max_map_count_not_read(
    mode: str, containment: str, required: int
) -> DoctorCheck:
    """Say why this host's vm.max_map_count was not read, and what still applies.

    Only a Docker VM manages the setting itself. A remote engine, or one whose
    host cannot be identified, still needs it on the host that runs it.
    """

    if mode == hostenv.DOCKER_VM:
        return _skipped(
            "max-map-count",
            "the selected Docker engine is not native Linux on this host, so it "
            "manages vm.max_map_count itself",
        )
    if mode == hostenv.DOCKER_LINUX_NATIVE:
        return _skipped(
            "max-map-count", "sysctl could not read vm.max_map_count on this host"
        )
    engine = (
        "the selected Docker engine is remote"
        if containment == "remote-unverified"
        else "doctor could not tell which host runs the selected Docker engine"
    )
    return DoctorCheck(
        "max-map-count",
        CheckStatus.WARNING,
        f"vm.max_map_count was not checked: {engine}. OpenSearch needs at least "
        f"{required} on that host.",
        "On the host that runs the selected Docker engine, run "
        f"{_sysctl_change(required)}",
    )


def _sysctl_change(required: int) -> str:
    """Return the sysctl change OpenSearch needs, for the user to run."""

    return (
        f"`sudo sysctl -w vm.max_map_count={required}` and add "
        f"`vm.max_map_count={required}` to /etc/sysctl.conf to keep it after a "
        "reboot."
    )


def _memory_check(run: Runner) -> DoctorCheck:
    """Warn when the engine has less memory than the full stack needs."""

    result = _probe(run, ["docker", "info", "--format", "{{.MemTotal}}"])
    raw = str(getattr(result, "stdout", "") or "").strip() if _ok(result) else ""
    if not raw.isdigit():
        return _skipped("docker-memory", "the daemon did not report its memory")
    memory_gb = int(raw) / 10**9
    if int(raw) > _FULL_STACK_MEMORY_BYTES:
        return DoctorCheck(
            "docker-memory",
            CheckStatus.PASSED,
            f"Docker can use {memory_gb:.1f} GB of memory.",
        )
    return DoctorCheck(
        "docker-memory",
        CheckStatus.WARNING,
        f"Docker can use {memory_gb:.1f} GB of memory; the full techvault stack "
        "needs more than 20 GB.",
        "Give Docker more memory (Docker Desktop: Settings > Resources; Colima: "
        "`colima start --memory <GiB>`), or start a smaller environment.",
    )


def _sentence(refusal: str) -> str:
    """Present a daemon gate's fixed refusal text as one sentence."""

    text = refusal.strip().rstrip(".")
    return f"{text[:1].upper()}{text[1:]}."


def _probe(run: Runner, argv: list[str]) -> object | None:
    """Run one read-only Docker query; any runner failure is no answer."""

    try:
        return run(argv, timeout=_PROBE_TIMEOUT_SECONDS)
    # A timeout, a missing binary or a transport error is reported as an
    # unanswered probe; its text, which can name an endpoint, is not kept.
    except Exception:
        return None


def _ok(result: object | None) -> bool:
    """Whether a probe answered with exit status zero."""

    return result is not None and getattr(result, "returncode", 1) == 0
