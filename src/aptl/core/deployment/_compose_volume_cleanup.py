"""Project-bounded cleanup for Compose volumes created before ``up``."""

from __future__ import annotations

import subprocess
from collections.abc import Callable

from aptl.core.deployment.errors import BackendTimeoutError

DockerRun = Callable[..., subprocess.CompletedProcess[str]]


def project_scoped_volume_names(
    project_name: str, run: DockerRun, *, timeout: int
) -> tuple[set[str], str]:
    """Return the volumes scoped to this Compose project, by name prefix.

    Teardown is scenario-agnostic — ``aptl lab stop`` does not know which bundle
    a running range was realized from — so it must discover its resources by
    project-scoped Docker identity, never by re-reading a filesystem Compose
    model that may belong to a different root than the one the scenario started
    from (issue #874). Compose names a project's implicit volumes
    ``<project>_<key>``, and APTL's ADR-043 content seeder creates its named
    volumes directly under the same prefix, so that prefix is the authoritative,
    root-independent, mechanism-independent scope. The ``com.docker.compose``
    project *label* is insufficient here: a seeder-created volume exists before
    ``compose up`` references it and therefore carries no Compose label, so a
    label filter silently leaves every seeded data volume behind.
    """
    listed, failures = _run_volume_command(
        run,
        ["docker", "volume", "ls", "--format", "{{.Name}}"],
        "Failed to list project volumes for cleanup",
        timeout=timeout,
    )
    if listed is None:
        return set(), failures[0] if failures else "Failed to list project volumes"
    prefix = f"{project_name}_"
    return {name for name in listed.stdout.splitlines() if name.startswith(prefix)}, ""


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
    except (BackendTimeoutError, OSError):
        return None, [failure_message]
    if result.returncode != 0:
        return None, [failure_message]
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
