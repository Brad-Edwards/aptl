"""Docker Compose lifecycle helpers shared by deployment backends."""

from __future__ import annotations

from typing import Any

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.logging import get_logger

log = get_logger("deployment.docker_compose")


def kill_compose_lab(
    backend: Any,
    profiles: list[str],
    *,
    timeout: int,
) -> tuple[bool, str]:
    """Emergency-stop all lab containers and cleanup realization networks."""

    kill_ok, kill_error = _run_compose_kill(
        backend,
        profiles,
        timeout=timeout,
    )
    _run_compose_down(backend, profiles, timeout=timeout)
    network_failures = backend.remove_project_networks()
    if network_failures:
        log.warning(
            "network cleanup failed: %s",
            "; ".join(network_failures[:5]),
        )

    error = _kill_error(kill_error, network_failures, kill_ok)
    success = not error
    if success:
        log.info("All lab containers stopped")
    return success, error


def _run_compose_kill(
    backend: Any,
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
    backend: Any,
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
