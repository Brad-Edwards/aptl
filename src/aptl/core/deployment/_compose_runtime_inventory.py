"""Checked project-runtime presence observation for Compose backends."""

from __future__ import annotations

import subprocess
from typing import Protocol

from aptl.core.deployment._compose_resource_ownership import OwnershipConflictError
from aptl.core.deployment.backend_host_inventory import ProjectRuntimePresence
from aptl.core.deployment.errors import BackendTimeoutError

_HOST_INVENTORY_TIMEOUT = 90


class _InventoryBackend(Protocol):
    """Backend surface required by checked runtime inventory."""

    _project_name: str

    def _load_resource_ownership(self) -> object | None:
        """Bind an existing workspace scope without publishing new state."""

        ...

    def _run(self, cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess:
        """Run one backend-scoped command."""

        ...


def _nonempty_lines(output: str) -> set[str]:
    """Return the distinct identifiers from bounded line-oriented output."""

    return {line.strip() for line in output.splitlines() if line.strip()}


class ComposeRuntimeInventoryMixin(object):
    """Observe project-owned containers and networks without conflating errors."""

    def observe_project_runtime(self) -> ProjectRuntimePresence:
        """Return checked runtime presence across both admitted container labels.

        The workspace scope is loaded first, because a start labels everything
        with the workspace-scoped project name. A newly built backend still holds
        the logical name until then, and would observe a different project.
        """

        try:
            self._load_resource_ownership()
        except OwnershipConflictError:
            return ProjectRuntimePresence(
                error="workspace ownership state is unavailable"
            )
        container_ids: set[str] = set()
        network_count = 0
        error = ""
        try:
            for project_label in (
                "com.docker.compose.project",
                "aptl.lifecycle.project",
            ):
                containers = self._run(
                    [
                        "docker",
                        "ps",
                        "-aq",
                        "--filter",
                        f"label={project_label}={self._project_name}",
                    ],
                    timeout=_HOST_INVENTORY_TIMEOUT,
                )
                if containers.returncode != 0:
                    error = "container observation failed"
                    break
                container_ids.update(_nonempty_lines(containers.stdout))
            if not error:
                networks = self._run(
                    [
                        "docker",
                        "network",
                        "ls",
                        "--filter",
                        f"label=com.docker.compose.project={self._project_name}",
                        "--format",
                        "{{.ID}}",
                    ],
                    timeout=_HOST_INVENTORY_TIMEOUT,
                )
                if networks.returncode != 0:
                    error = "network observation failed"
                else:
                    network_count = len(_nonempty_lines(networks.stdout))
        except (BackendTimeoutError, OSError):
            error = "runtime observation failed"
        if error:
            return ProjectRuntimePresence(error=error)
        return ProjectRuntimePresence(
            container_count=len(container_ids), network_count=network_count
        )
