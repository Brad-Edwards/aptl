"""Read-only host and container-runtime checks for ``aptl doctor`` (#1218).

Each check observes one documented prerequisite and, when it is not met, names
the fix. Nothing here writes to the host, the workspace or the Docker daemon:
the probes are version and inspection queries, and the Docker engine checks
(:mod:`aptl.core._doctor_runtime`) go through the configured deployment
backend's runner so an explicitly selected endpoint is the daemon that
answers. Summaries and fixes carry only fixed text, parsed versions and
counts, so they cannot leak daemon output, native IDs, secrets, environment
values, argv or host paths. The reused ``vm.max_map_count`` check logs raw
sysctl output, so its logger is silenced while doctor runs.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from aptl.core import hostenv, sysreqs
from aptl.core.config import AptlConfig, find_config, load_config
from aptl.core.lifecycle_guard import canonical_lifecycle_project_root

_PROBE_TIMEOUT_SECONDS = 30
_VERSION_TEXT = re.compile(r"v?(\d+)\.(\d+)[0-9A-Za-z.+-]{0,40}")
_MIN_NODE_MAJOR = 20
_NO_PROJECT_DIRECTORY = "the project directory does not exist (see project-config)"


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
    """Check the workspace, host tools and the selected Docker runtime.

    Every run reports the same checks in the same order. A check that cannot
    run is skipped, and its summary names the check that stopped it.
    """

    from aptl.core._doctor_runtime import runtime_checks

    config, project_root, checks = _workspace_checks(project_dir)
    checks.extend(_host_tool_checks(which))
    with _silenced(sysreqs.log):
        checks.extend(runtime_checks(config, project_root, which))
    return DoctorReport(tuple(checks))


def _workspace_checks(
    project_dir: Path,
) -> tuple[AptlConfig, Path | None, list[DoctorCheck]]:
    """Check the project configuration and that the workspace is writable.

    The project root is found the way ``aptl lab start`` and ``stop`` find it:
    the nearest directory, from ``project_dir`` up, that holds aptl.json. The
    root is ``None`` when the project directory does not exist.
    """

    project_root = canonical_lifecycle_project_root(project_dir)
    if not project_root.is_dir():
        missing = DoctorCheck(
            "project-config",
            CheckStatus.FAILED,
            "The project directory does not exist or is not a directory.",
            "Pass an existing project directory with `--project-dir`, or create "
            "one with `aptl lab init <directory>`.",
        )
        return (
            AptlConfig(),
            None,
            [missing, _skipped("workspace-writable", _NO_PROJECT_DIRECTORY)],
        )
    config, config_check = _config_check(project_root)
    return config, project_root, [config_check, _writable_check(project_root)]


def _config_check(project_root: Path) -> tuple[AptlConfig, DoctorCheck]:
    """Load the project's aptl.json, or say why it cannot be used."""

    config_path = find_config(project_root)
    if config_path is None:
        return AptlConfig(), DoctorCheck(
            "project-config",
            CheckStatus.FAILED,
            "No aptl.json was found in the project directory or its parents.",
            "Run `aptl lab init <directory>`, then run `aptl doctor` there or "
            "pass `--project-dir`.",
        )
    try:
        config = load_config(config_path)
    except (OSError, ValueError):
        return AptlConfig(), DoctorCheck(
            "project-config",
            CheckStatus.FAILED,
            "aptl.json is not valid.",
            "Run `aptl config validate` to see why, then repair aptl.json.",
        )
    return config, DoctorCheck(
        "project-config", CheckStatus.PASSED, "aptl.json is valid."
    )


def _writable_check(project_root: Path) -> DoctorCheck:
    """Check that this user can write the project directory."""

    if os.access(project_root, os.W_OK):
        return DoctorCheck(
            "workspace-writable",
            CheckStatus.PASSED,
            "The project directory is writable.",
        )
    return DoctorCheck(
        "workspace-writable",
        CheckStatus.FAILED,
        "The project directory is not writable by this user.",
        "Run aptl as a user that can write the project directory, or create "
        "a project you own with `aptl lab init <directory>`.",
    )


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


@contextmanager
def _silenced(logger: logging.Logger) -> Iterator[None]:
    """Drop one logger's records for the duration of a doctor run.

    The reused vm.max_map_count check logs sysctl's raw stderr. The CLI sets
    up no log handler, so Python's last-resort handler would print that text
    to the terminal beside the report.
    """

    level = logger.level
    logger.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        logger.setLevel(level)


def _skipped(check_id: str, reason: str) -> DoctorCheck:
    """Return a check that could not run, and why."""

    return DoctorCheck(check_id, CheckStatus.SKIPPED, f"Not checked: {reason}.")


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


def _version_text(raw: object) -> str | None:
    """Return a bounded version string, or ``None`` for anything else."""

    text = str(raw or "").strip()
    return text if _VERSION_TEXT.fullmatch(text) else None


def _major_minor(raw: object) -> tuple[int, int] | None:
    """Parse ``major.minor`` from a version string such as ``v20.11.1``."""

    match = _VERSION_TEXT.fullmatch(str(raw or "").strip())
    return (int(match.group(1)), int(match.group(2))) if match else None
