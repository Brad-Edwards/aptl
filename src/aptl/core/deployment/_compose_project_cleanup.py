"""Project-scoped residual container cleanup for Compose backends."""

from __future__ import annotations

from typing import Protocol

from aptl.core.deployment.errors import BackendTimeoutError


class _CleanupBackend(Protocol):
    """Backend surface required by the project-container cleanup helper."""

    _project_name: str

    def _run(self, cmd: list[str], *, timeout: int): ...


def _remove_labelled_containers(
    backend: _CleanupBackend,
    *,
    label: str,
    list_failure: str,
    remove_failure: str,
) -> list[str]:
    """Remove every container carrying ``label`` and return bounded failures."""

    failure = ""
    try:
        list_result = backend._run(
            ["docker", "ps", "-aq", "--filter", f"label={label}"], timeout=30
        )
        if list_result.returncode != 0:
            failure = list_failure
        else:
            identifiers = [
                line.strip() for line in list_result.stdout.splitlines() if line.strip()
            ]
            if identifiers:
                remove_result = backend._run(
                    ["docker", "rm", "-f", *identifiers], timeout=60
                )
                if remove_result.returncode != 0:
                    failure = remove_failure
    except (BackendTimeoutError, OSError):
        failure = remove_failure
    return [failure] if failure else []


class ComposeProjectCleanupMixin(object):
    """Remove project-owned containers that Compose may leave behind."""

    def remove_generic_materializer_containers(self) -> list[str]:
        """Force-remove containers realized directly by the generic materializer."""

        return _remove_labelled_containers(
            self,
            label=f"aptl.lifecycle.project={self._project_name}",
            list_failure="failed to list generic-materializer containers",
            remove_failure="failed to remove generic-materializer containers",
        )

    def remove_project_containers(self) -> list[str]:
        """Force-remove residual containers carrying the Compose project identity."""

        return _remove_labelled_containers(
            self,
            label=f"com.docker.compose.project={self._project_name}",
            list_failure="failed to list residual project containers",
            remove_failure="failed to remove residual project containers",
        )
