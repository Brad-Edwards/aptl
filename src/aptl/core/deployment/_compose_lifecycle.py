"""Docker Compose lifecycle helpers shared by deployment backends."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.deployment.backend_host_inventory import ProjectRuntimePresence
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")


class _ComposeLifecycleBackend(Protocol):
    """Backend operations needed by the compose lifecycle helpers."""

    def _run(
        self,
        cmd: list[str],
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess:
        """Run one backend-scoped command."""

    def _build_command(
        self,
        action: str,
        profiles: list[str],
        *,
        compose_files: Sequence[Path] | None = None,
    ) -> list[str]:
        """Build a Docker Compose command."""

    def remove_project_networks(self) -> list[str]:
        """Remove leftover project-scoped realization networks."""

    def remove_generic_materializer_containers(self) -> list[str]:
        """Force-remove containers the generic materializer started directly."""

    def remove_project_containers(self) -> list[str]:
        """Force-remove residual project-labelled containers."""

    def observe_project_runtime(self) -> ProjectRuntimePresence:
        """Return checked residual project container/network presence."""


def kill_compose_lab(
    backend: _ComposeLifecycleBackend,
    profiles: list[str],
    *,
    timeout: int,
) -> tuple[bool, str]:
    """Emergency-stop all lab containers and cleanup realization networks.

    `docker compose kill`/`down` only affects containers Compose itself
    started; a node the generic materializer realized directly (ADR-048) is
    invisible to both, so it survives an emergency stop unless force-removed
    separately.
    """

    kill_ok, kill_error = _run_compose_kill(
        backend,
        profiles,
        timeout=timeout,
    )
    _run_compose_down(backend, profiles, timeout=timeout)
    container_failures = backend.remove_generic_materializer_containers()
    container_failures += backend.remove_project_containers()
    if container_failures:
        log.warning(
            "generic-materializer container cleanup failed: %s",
            "; ".join(container_failures[:5]),
        )
    network_failures = backend.remove_project_networks()
    if network_failures:
        log.warning(
            "network cleanup failed: %s",
            "; ".join(network_failures[:5]),
        )

    verification_failures = _kill_verification_failures(backend)
    error = _kill_error(
        kill_error,
        container_failures + network_failures + verification_failures,
        kill_ok,
    )
    success = not error
    if success:
        log.info("All lab containers stopped")
    return success, error


def _run_compose_kill(
    backend: _ComposeLifecycleBackend,
    profiles: list[str],
    *,
    timeout: int,
) -> tuple[bool, str]:
    """Run docker compose kill and return its success state and hard error."""

    kill_cmd = backend._build_command("kill", profiles)

    log.info("Running: %s", " ".join(kill_cmd))
    kill_ok = False
    error = ""
    try:
        result = backend._run(kill_cmd, timeout=timeout)
        kill_ok = result.returncode == 0
        if not kill_ok:
            log.warning("docker compose kill returned non-zero")
    except BackendTimeoutError:
        log.warning("docker compose kill timed out after %ds", timeout)
    except OSError:
        error = "docker compose kill failed"
        log.error(error)
    return kill_ok, error


def _run_compose_down(
    backend: _ComposeLifecycleBackend,
    profiles: list[str],
    *,
    timeout: int,
) -> None:
    """Run docker compose down as best-effort cleanup after kill."""

    down_cmd = backend._build_command("down", profiles=profiles)
    log.info("Running: %s", " ".join(down_cmd))
    try:
        result = backend._run(down_cmd, timeout=timeout)
        if result.returncode != 0:
            log.warning("docker compose down returned non-zero")
    except BackendTimeoutError:
        log.warning("docker compose down timed out after %ds", timeout)
    except OSError:
        log.warning("docker compose down failed")


def _kill_error(
    kill_error: str,
    network_failures: list[str],
    kill_ok: bool,
) -> str:
    """Return the operator-facing kill failure reason, if any."""

    error = kill_error
    if not error and network_failures:
        error = "; ".join(network_failures[:5])
    # A non-zero Compose kill is recoverable when the bounded down/residual
    # cleanup path proves the project runtime absent. The terminal runtime fact
    # is authoritative; raw Compose stderr is not exposed.
    if not error and not kill_ok:
        log.info("Compose kill returned non-zero but cleanup verified absence")
    return error


def _kill_verification_failures(
    backend: _ComposeLifecycleBackend,
) -> list[str]:
    """Require checked proof that emergency cleanup removed project runtime."""

    presence = backend.observe_project_runtime()
    if presence.error:
        return ["failed to verify emergency project cleanup"]
    if presence.present:
        return [
            "project runtime artifacts remain after emergency cleanup "
            f"(containers={presence.container_count}, networks={presence.network_count})"
        ]
    return []
