"""Project-bounded cleanup for Compose volumes created before ``up``."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import yaml

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.redaction import redact

DockerRun = Callable[..., subprocess.CompletedProcess[str]]


def _declared_volumes(compose: object) -> tuple[dict[object, object] | None, str]:
    """Validate and return the top-level Compose volume mapping."""
    if not isinstance(compose, dict):
        return None, "invalid Compose"
    declared = compose.get("volumes") or {}
    if not isinstance(declared, dict):
        return None, "invalid volumes"
    return declared, ""


def project_scoped_volume_names(
    project_dir: Path, project_name: str
) -> tuple[set[str], str]:
    """Return implicit, non-external volume names scoped to one project."""
    compose_path = project_dir / "docker-compose.yml"
    try:
        compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return set(), f"Failed to read project volumes for cleanup: {exc}"

    declared, error = _declared_volumes(compose)
    if declared is None:
        return set(), f"Failed to read project volumes for cleanup: {error}"

    names = set()
    for key, config in declared.items():
        settings = config if isinstance(config, dict) else {}
        if isinstance(key, str) and not (
            settings.get("external") or settings.get("name")
        ):
            names.add(f"{project_name}_{key}")
    return names, ""


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
