"""Docker Compose lifecycle helpers shared by deployment backends."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from aptl.core.deployment.errors import BackendTimeoutError
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

    error = _kill_error(kill_error, container_failures + network_failures, kill_ok)
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

    kill_cmd = ["docker", "compose"]
    for profile in profiles:
        kill_cmd.extend(["--profile", profile])
    kill_cmd.append("kill")

    log.info("Running: %s", " ".join(kill_cmd))
    kill_ok = False
    error = ""
    try:
        result = backend._run(kill_cmd, timeout=timeout)
        kill_ok = result.returncode == 0
        if not kill_ok:
            log.warning("docker compose kill stderr: %s", result.stderr.strip())
    except BackendTimeoutError:
        log.warning("docker compose kill timed out after %ds", timeout)
    except OSError as exc:
        error = f"docker compose kill failed: {exc}"
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
            log.warning("docker compose down stderr: %s", result.stderr.strip())
    except BackendTimeoutError:
        log.warning("docker compose down timed out after %ds", timeout)
    except OSError as exc:
        log.warning("docker compose down failed: %s", exc)


def _kill_error(
    kill_error: str,
    network_failures: list[str],
    kill_ok: bool,
) -> str:
    """Return the operator-facing kill failure reason, if any."""

    error = kill_error
    if not error and network_failures:
        error = "; ".join(network_failures[:5])
    if not error and not kill_ok:
        error = "docker compose kill returned non-zero"
    return error
