"""Read-only host and container-runtime checks for ``aptl doctor`` (#1218).

Each check observes one documented prerequisite and, when it is not met, names
the fix. Nothing here writes to the host, the workspace or the Docker daemon:
the probes are version and inspection queries, issued through the configured
deployment backend's runner so an explicitly selected endpoint is the daemon
that answers. Raw probe output never reaches a message. Summaries carry only
fixed text, parsed versions and counts, so they cannot leak daemon output,
native IDs, secrets, environment values, argv or host paths.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from aptl.core import hostenv, sysreqs
from aptl.core.config import AptlConfig, find_config, load_config

_PROBE_TIMEOUT_SECONDS = 30
_VERSION_TEXT = re.compile(r"v?(\d+)\.(\d+)[0-9A-Za-z.+-]{0,40}")
# The prerequisites page: "the full `techvault` stack needs more than 20GB".
_FULL_STACK_MEMORY_BYTES = 20 * 10**9
_MIN_NODE_MAJOR = 20
_MIN_COMPOSE_MAJOR = 2


class CheckStatus(str, Enum):
    """Verdict of one doctor check; the values are stable output words."""

    PASSED = "pass"
    WARNING = "warn"
    FAILED = "fail"
    SKIPPED = "skip"


@dataclass(frozen=True)
class DoctorCheck:
    """One observed prerequisite, with the fix when it is not met."""

    check_id: str
    status: CheckStatus
    summary: str
    fix: str = ""


@dataclass(frozen=True)
class DoctorReport:
    """Every check from one ``aptl doctor`` run, in a stable order."""

    checks: tuple[DoctorCheck, ...]

    def count(self, status: CheckStatus) -> int:
        """Return how many checks ended with ``status``."""

        return sum(1 for check in self.checks if check.status is status)

    @property
    def ok(self) -> bool:
        """Whether no check failed; warnings and skips do not fail a run."""

        return self.count(CheckStatus.FAILED) == 0


Runner = Callable[..., Any]
Which = Callable[[str], str | None]


def run_doctor(project_dir: Path, *, which: Which = shutil.which) -> DoctorReport:
    """Check the workspace, host tools and the selected Docker runtime."""

    config, project_root, checks = _workspace_checks(project_dir)
    checks.extend(_host_tool_checks(which))
    if which("docker") is None:
        checks.append(
            _skipped("docker-daemon", "the Docker CLI is not on PATH (see docker-cli)")
        )
    else:
        checks.extend(_runtime_checks(config, project_root))
    return DoctorReport(tuple(checks))


def _workspace_checks(
    project_dir: Path,
) -> tuple[AptlConfig, Path, list[DoctorCheck]]:
    """Check the project configuration and that the workspace is writable."""

    config_path = find_config(project_dir)
    config = AptlConfig()
    project_root = project_dir
    if config_path is None:
        config_check = DoctorCheck(
            "project-config",
            CheckStatus.FAILED,
            "No aptl.json was found in the project directory or its parents.",
            "Run `aptl lab init <directory>`, then run `aptl doctor` there or "
            "pass `--project-dir`.",
        )
    else:
        project_root = config_path.parent
        try:
            config = load_config(config_path)
        except (OSError, ValueError):
            config_check = DoctorCheck(
                "project-config",
                CheckStatus.FAILED,
                "aptl.json is not valid.",
                "Run `aptl config validate` to see why, then repair aptl.json.",
            )
        else:
            config_check = DoctorCheck(
                "project-config", CheckStatus.PASSED, "aptl.json is valid."
            )
    writable = DoctorCheck(
        "workspace-writable",
        CheckStatus.PASSED,
        "The project directory is writable.",
    )
    if not os.access(project_root, os.W_OK):
        writable = DoctorCheck(
            "workspace-writable",
            CheckStatus.FAILED,
            "The project directory is not writable by this user.",
            "Run aptl as a user that can write the project directory, or create "
            "a project you own with `aptl lab init <directory>`.",
        )
    return config, project_root, [config_check, writable]


def _host_tool_checks(which: Which) -> list[DoctorCheck]:
    """Check the host tools that lab start invokes directly."""

    docker = DoctorCheck(
        "docker-cli", CheckStatus.PASSED, "The Docker CLI is on PATH."
    )
    if which("docker") is None:
        docker = DoctorCheck(
            "docker-cli",
            CheckStatus.FAILED,
            "The Docker CLI is not on PATH.",
            "Install Docker Desktop, or Docker Engine 28.0 or newer with the "
            "Compose and Buildx plugins (see Prerequisites).",
        )
    ssh_keygen = DoctorCheck(
        "ssh-keygen", CheckStatus.PASSED, "ssh-keygen is on PATH."
    )
    if which("ssh-keygen") is None:
        ssh_keygen = DoctorCheck(
            "ssh-keygen",
            CheckStatus.FAILED,
            "ssh-keygen is not on PATH; lab start generates the lab SSH keys "
            "with it.",
            _ssh_keygen_fix(),
        )
    return [docker, ssh_keygen, _node_check(which)]


def _ssh_keygen_fix() -> str:
    """Return the platform's way to get the OpenSSH client."""

    if hostenv.host_os() == hostenv.OS_WINDOWS:
        return (
            "Enable the OpenSSH Client optional feature, or use Git for Windows "
            "or WSL2."
        )
    return "Install the OpenSSH client package for your system."


def _node_check(which: Which) -> DoctorCheck:
    """Warn when the MCP servers cannot be built; the lab still starts."""

    fix = f"Install Node.js {_MIN_NODE_MAJOR} or newer with npm."
    node = which("node")
    if node is None or which("npm") is None:
        return DoctorCheck(
            "node-npm",
            CheckStatus.WARNING,
            "Node.js and npm are not both on PATH, so the lab starts without its "
            "MCP servers and reports degraded.",
            fix,
        )
    version = _major_minor(_local_output([node, "--version"]))
    if version is None or version[0] < _MIN_NODE_MAJOR:
        return DoctorCheck(
            "node-npm",
            CheckStatus.WARNING,
            f"Node.js {_MIN_NODE_MAJOR} or newer was not found, so the MCP "
            "servers may not build.",
            fix,
        )
    return DoctorCheck(
        "node-npm",
        CheckStatus.PASSED,
        f"Node.js {version[0]}.{version[1]} and npm are on PATH.",
    )


def _runtime_checks(config: AptlConfig, project_root: Path) -> list[DoctorCheck]:
    """Check the daemon the configured deployment backend would drive."""

    from aptl.core.deployment import get_backend

    try:
        backend = get_backend(config, project_root)
    except ValueError:
        return [
            DoctorCheck(
                "docker-daemon",
                CheckStatus.FAILED,
                "The configured deployment backend cannot be created.",
                "Run `aptl config validate` and repair the deployment settings "
                "in aptl.json.",
            )
        ]
    # The Compose and Buildx plugins belong to the Docker CLI, so they are
    # checked even when the daemon does not answer.
    plugins = [_compose_check(backend._run), _buildx_check()]
    daemon = _daemon_check(backend._run)
    if daemon.status is not CheckStatus.PASSED:
        reason = "the Docker daemon did not answer (see docker-daemon)"
        return [
            daemon,
            *plugins,
            *(
                _skipped(check_id, reason)
                for check_id in (
                    "rootful-daemon",
                    "systemd-substrate",
                    "max-map-count",
                    "docker-memory",
                )
            ),
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
    """Apply the systemd-substrate daemon gate (cgroup v2, Engine 28.0+)."""

    from aptl.core.deployment._compose_substrate_gate import (
        require_substrate_daemon_support,
    )
    from aptl.core.deployment.errors import BackendSeedError

    if rootful.status is not CheckStatus.PASSED:
        return _skipped(
            "systemd-substrate", "the daemon is not rootful (see rootful-daemon)"
        )
    refusal = None
    try:
        require_substrate_daemon_support(run)
    except BackendSeedError as exc:
        refusal = str(exc)
    if refusal is None:
        return DoctorCheck(
            "systemd-substrate",
            CheckStatus.PASSED,
            "The daemon runs cgroup v2 with Docker Engine 28.0 or newer.",
        )
    return DoctorCheck(
        "systemd-substrate",
        CheckStatus.FAILED,
        _sentence(refusal),
        "Use Docker Engine 28.0 or newer on a cgroup v2 host (see Prerequisites).",
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


def _max_map_count_check(backend: object) -> DoctorCheck:
    """Apply lab start's vm.max_map_count check to the selected daemon's host."""

    from aptl.core.execution_boundary import observe_execution_boundary

    boundary = observe_execution_boundary(backend)  # type: ignore[arg-type]
    mode = sysreqs.docker_mode_for_containment(boundary.host_containment)
    result = sysreqs.check_max_map_count(selected_mode=mode)
    if not result.applicable:
        reason = (
            "this host has no vm.max_map_count setting"
            if mode == hostenv.DOCKER_LINUX_NATIVE
            else "the selected Docker engine is not native Linux on this host, "
            "so it manages vm.max_map_count itself"
        )
        return _skipped("max-map-count", reason)
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
        f"Run `sudo sysctl -w vm.max_map_count={result.required_value}` and add "
        f"`vm.max_map_count={result.required_value}` to /etc/sysctl.conf to keep "
        "it after a reboot.",
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


def _skipped(check_id: str, reason: str) -> DoctorCheck:
    """Return a check that could not run, and why."""

    return DoctorCheck(check_id, CheckStatus.SKIPPED, f"Not checked: {reason}.")


def _probe(run: Runner, argv: list[str]) -> object | None:
    """Run one read-only Docker query; any runner failure is no answer."""

    try:
        return run(argv, timeout=_PROBE_TIMEOUT_SECONDS)
    # A timeout, a missing binary or a transport error is reported as an
    # unanswered probe; its text, which can name an endpoint, is not kept.
    except Exception:
        return None


def _local_output(argv: list[str]) -> str:
    """Return a local tool's stdout, or nothing when it cannot run."""

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _ok(result: object | None) -> bool:
    """Whether a probe answered with exit status zero."""

    return result is not None and getattr(result, "returncode", 1) == 0


def _version_text(raw: object) -> str | None:
    """Return a bounded version string, or ``None`` for anything else."""

    text = str(raw or "").strip()
    return text if _VERSION_TEXT.fullmatch(text) else None


def _major_minor(raw: object) -> tuple[int, int] | None:
    """Parse ``major.minor`` from a version string such as ``v20.11.1``."""

    match = _VERSION_TEXT.fullmatch(str(raw or "").strip())
    return (int(match.group(1)), int(match.group(2))) if match else None
