"""Project-bounded cleanup for Compose volumes created before ``up``."""

from __future__ import annotations

import subprocess
from collections.abc import Callable

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.redaction import redact

DockerRun = Callable[..., subprocess.CompletedProcess[str]]

_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"


def project_scoped_volume_names(
    project_name: str, run: DockerRun, *, timeout: int
) -> tuple[set[str], str]:
    """Return the volumes Compose created for this project, by runtime label.

    Teardown is scenario-agnostic — ``aptl lab stop`` does not know which bundle
    a running range was realized from — so it must discover its resources by
    project-scoped Docker identity, never by re-reading a filesystem Compose
    model that may belong to a different root than the one the scenario started
    from (issue #874). Docker Compose labels every volume it creates with
    ``com.docker.compose.project``, so that label is the authoritative,
    root-independent scope.
    """
    listed, failures = _run_volume_command(
        run,
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label={_COMPOSE_PROJECT_LABEL}={project_name}",
            "--format",
            "{{.Name}}",
        ],
        "Failed to list project volumes for cleanup",
        timeout=timeout,
    )
    if listed is None:
        return set(), failures[0] if failures else "Failed to list project volumes"
    return {name for name in listed.stdout.splitlines() if name}, ""


def _run_volume_command(
    run: DockerRun,
    command: list[str],
    failure_message: str,
    *,
    timeout: int,
) -> tuple[subprocess.CompletedProcess[str] | None, list[str]]:
    """Run one Docker volume command and normalize its failure."""
    try:
        result = run(command, timeout=timeout)
    except (BackendTimeoutError, OSError) as exc:
        return None, [f"{failure_message}: {exc}"]
    if result.returncode != 0:
        return None, [f"{failure_message}: {redact(result.stderr.strip())}"]
    return result, []


def remove_leftover_project_volumes(
    expected: set[str], run: DockerRun, *, timeout: int
) -> list[str]:
    """Remove only expected project volumes still present after ``down -v``."""
    failures: list[str] = []
    if expected:
        listed, failures = _run_volume_command(
            run,
            ["docker", "volume", "ls", "--format", "{{.Name}}"],
            "Failed to list project volumes for cleanup",
            timeout=timeout,
        )
        if listed is not None:
            leftovers = sorted(expected & set(listed.stdout.splitlines()))
            if leftovers:
                _, failures = _run_volume_command(
                    run,
                    ["docker", "volume", "rm", *leftovers],
                    "Failed to remove project volumes",
                    timeout=timeout,
                )
    return failures
