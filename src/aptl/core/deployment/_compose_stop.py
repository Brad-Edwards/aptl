"""Project-scoped Docker Compose stop and cleanup workflow."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from aptl.core.deployment._compose_volume_cleanup import (
    project_scoped_volume_names,
    remove_leftover_project_volumes,
)
from aptl.core.deployment.backend_host_inventory import ProjectRuntimePresence
from aptl.core.deployment.errors import BackendTimeoutError
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

    def remove_project_networks(self) -> list[str]:
        """Remove leftover project-scoped realization networks."""

        ...

    def remove_generic_materializer_containers(self) -> list[str]:
        """Force-remove containers the generic materializer started directly."""

        ...

    def remove_project_containers(self) -> list[str]:
        """Force-remove residual containers scoped to the Compose project."""

        ...

    def observe_project_runtime(self) -> ProjectRuntimePresence:
        """Return checked residual project container/network presence."""

        ...


def stop_compose_lab(
    backend: _ComposeStopBackend,
    profiles: list[str],
    *,
    remove_volumes: bool,
    timeout: int,
) -> LabResult:
    """Stop Compose services and clean project-scoped networks and volumes."""

    volume_names, discovery_error = _volume_inventory(backend, remove_volumes, timeout)
    # Teardown is scenario-agnostic and resolves the running range by project
    # identity, not by a filesystem Compose model that may belong to a different
    # root than the scenario started from. ``docker compose -p <project> down``
    # removes the project's containers/networks by label; project-scoped volume
    # cleanup below owns the volumes (issue #874).
    return _run_stop(
        backend,
        profiles,
        None,
        remove_volumes,
        volume_names,
        discovery_error,
        timeout,
    )


def _volume_inventory(
    backend: _ComposeStopBackend, remove_volumes: bool, timeout: int
) -> tuple[set[str], str]:
    """Discover project volumes only for destructive cleanup, by runtime label."""

    return (
        project_scoped_volume_names(backend.project_name, backend._run, timeout=timeout)
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
    """Run bounded project cleanup and verify the runtime is absent."""

    failures = backend.remove_generic_materializer_containers()
    cmd = backend._build_command("down", profiles, compose_files=compose_files)
    if remove_volumes:
        cmd.append("-v")
    log.info("Stopping lab (remove_volumes=%s)", remove_volumes)
    compose_recovered = _run_compose_down(backend, cmd, timeout)
    failures.extend(
        _cleanup_failures(
            backend, remove_volumes, volume_names, discovery_error, timeout
        )
    )
    failures.extend(_verification_failures(backend))
    return _cleanup_result(failures, compose_recovered=compose_recovered)


def _run_compose_down(
    backend: _ComposeStopBackend, cmd: list[str], timeout: int
) -> bool:
    """Attempt Compose teardown and report whether fallback cleanup is needed."""

    try:
        result = backend._run(cmd, timeout=timeout)
    except (BackendTimeoutError, OSError):
        log.warning("Compose teardown did not complete; continuing project cleanup")
        return True
    if result.returncode != 0:
        log.warning("Compose teardown returned non-zero; continuing project cleanup")
        return True
    return False


def _verification_failures(backend: _ComposeStopBackend) -> list[str]:
    """Return a failure unless checked observation proves runtime absence."""

    presence = backend.observe_project_runtime()
    if presence.error:
        return ["Failed to verify project runtime cleanup"]
    if presence.present:
        return [
            "Project runtime artifacts remain after cleanup "
            f"(containers={presence.container_count}, networks={presence.network_count})"
        ]
    return []


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

    failures = backend.remove_project_containers()
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


def _cleanup_result(
    failures: list[str], *, compose_recovered: bool = False
) -> LabResult:
    """Translate cleanup failures into the public lab result."""

    if failures:
        error = "; ".join(failures[:5])
        log.error("Lab cleanup failed: %s", error)
        return LabResult(success=False, error=error)
    if compose_recovered:
        log.info("Lab stopped successfully through residual project cleanup")
        return LabResult(success=True, message="Lab stopped after recovery cleanup")
    log.info("Lab stopped successfully")
    return LabResult(success=True, message="Lab stopped")
