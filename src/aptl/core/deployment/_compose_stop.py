"""Project-scoped Docker Compose stop and cleanup workflow."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from aptl.core.credentials import PathContainmentError
from aptl.core.deployment._compose_volume_cleanup import (
    project_scoped_volume_names,
    remove_leftover_project_volumes,
)
from aptl.core.lab_types import LabResult
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")


class _ComposeStopBackend(Protocol):
    """Backend surface required by the Compose stop workflow."""

    project_dir: Path
    project_name: str

    def _build_command(
        self,
        action: str,
        profiles: list[str],
        *,
        compose_files: Sequence[Path] | None = None,
    ) -> list[str]:
        """Build a backend-scoped Compose command."""

        ...

    def _run(
        self, cmd: list[str], *, timeout: int | None = None
    ) -> subprocess.CompletedProcess:
        """Run a backend-scoped command."""

        ...

    def _stateful_teardown_compose_files(self) -> tuple[Path, ...] | None:
        """Return validated Compose inputs for stateful teardown."""

        ...

    def remove_project_networks(self) -> list[str]:
        """Remove leftover project-scoped realization networks."""

        ...

    def remove_generic_materializer_containers(self) -> list[str]:
        """Force-remove containers the generic materializer started directly."""

        ...


def stop_compose_lab(
    backend: _ComposeStopBackend,
    profiles: list[str],
    *,
    remove_volumes: bool,
    timeout: int,
) -> LabResult:
    """Stop Compose services and clean project-scoped networks and volumes."""

    volume_names, discovery_error = _volume_inventory(backend, remove_volumes)
    try:
        compose_files = backend._stateful_teardown_compose_files()
    except PathContainmentError:
        return LabResult(
            success=False,
            error="Stateful teardown model failed containment validation.",
        )
    return _run_stop(
        backend,
        profiles,
        compose_files,
        remove_volumes,
        volume_names,
        discovery_error,
        timeout,
    )


def _volume_inventory(
    backend: _ComposeStopBackend, remove_volumes: bool
) -> tuple[set[str], str]:
    """Discover project volumes only for destructive cleanup."""

    return (
        project_scoped_volume_names(backend.project_dir, backend.project_name)
        if remove_volumes
        else (set(), "")
    )


def _run_stop(
    backend: _ComposeStopBackend,
    profiles: list[str],
    compose_files: tuple[Path, ...] | None,
    remove_volumes: bool,
    volume_names: set[str],
    discovery_error: str,
    timeout: int,
) -> LabResult:
    """Run Compose down and return its cleanup result."""

    cmd = backend._build_command("down", profiles, compose_files=compose_files)
    if remove_volumes:
        cmd.append("-v")
    log.info("Stopping lab (remove_volumes=%s)", remove_volumes)
    result = backend._run(cmd)
    if result.returncode != 0:
        log.error("Lab stop failed: %s", result.stderr)
        return LabResult(success=False, error=result.stderr)
    failures = _cleanup_failures(
        backend, remove_volumes, volume_names, discovery_error, timeout
    )
    return _cleanup_result(failures)


def _cleanup_failures(
    backend: _ComposeStopBackend,
    remove_volumes: bool,
    volume_names: set[str],
    discovery_error: str,
    timeout: int,
) -> list[str]:
    """Collect project cleanup failures after Compose stops.

    Generic-materializer containers (ADR-048) first: `docker compose down`
    never touches them (Compose didn't start them), so they would otherwise
    stay attached to the very networks/volumes cleaned up next, failing that
    removal outright with "network has active endpoints".
    """

    failures = backend.remove_generic_materializer_containers()
    failures += backend.remove_project_networks()
    if not remove_volumes:
        return failures
    if discovery_error:
        failures.append(discovery_error)
    else:
        failures.extend(
            remove_leftover_project_volumes(volume_names, backend._run, timeout=timeout)
        )
    return failures


def _cleanup_result(failures: list[str]) -> LabResult:
    """Translate cleanup failures into the public lab result."""

    if failures:
        error = "; ".join(failures[:5])
        log.error("Lab cleanup failed: %s", error)
        return LabResult(success=False, error=error)
    log.info("Lab stopped successfully")
    return LabResult(success=True, message="Lab stopped")
