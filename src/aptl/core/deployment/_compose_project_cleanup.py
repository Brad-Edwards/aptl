"""Project-scoped residual container cleanup for Compose backends."""

from __future__ import annotations

import subprocess
from typing import Protocol

from aptl.core.deployment.errors import BackendTimeoutError
from aptl.core.ephemeral_containers import (
    EphemeralContainer,
    remove_container_command,
    stranded_helpers_command,
)

_HELPER_CLEANUP_TIMEOUT = 60


class _CleanupBackend(Protocol):
    """Backend surface required by the project-container cleanup helper."""

    _project_name: str

    def _remove_owned_containers(self, managed_by: str) -> list[str]:
        """Remove only freshly verified receipt-owned native container IDs."""

        ...

    def _load_resource_ownership(self) -> object | None: ...

    def _run(
        self, cmd: list[str], *, timeout: int | None = None
    ) -> subprocess.CompletedProcess: ...


class ComposeProjectCleanupMixin(object):
    """Remove project-owned containers that Compose may leave behind."""

    def remove_generic_materializer_containers(self) -> list[str]:
        """Force-remove containers realized directly by the generic materializer."""

        return self._remove_owned_containers("direct")

    def remove_project_containers(self) -> list[str]:
        """Force-remove residual containers carrying the Compose project identity."""

        return self._remove_owned_containers("compose")

    def _ephemeral_project(self) -> str | None:
        """Return this workspace's project if it already exists, creating nothing.

        Loading rather than ensuring ownership keeps a helper from publishing
        workspace state or fixing the start attempt's identity as a side effect.
        """

        ownership = self._load_resource_ownership()
        return None if ownership is None else ownership.project_name

    def _ephemeral_container(self, role: str) -> EphemeralContainer:
        """Mint a helper scoped to this workspace's project when it has one."""

        return EphemeralContainer.for_role(role, project=self._ephemeral_project())

    def remove_stranded_helpers(self) -> list[str]:
        """Remove this project's helpers that a killed process left not running.

        A helper that had started finishes and is auto-removed; one killed
        between create and start stays ``Created`` with nothing to reap it.
        Only helpers of this workspace's project that are not running are
        selected, so an in-flight helper and every node container are safe.
        """

        # A daemon that times out or is unreachable is a cleanup failure to
        # report, like every other teardown step, never an exception that
        # aborts the rest of teardown.
        try:
            project = self._ephemeral_project()
            if project is None:
                return []
            listed = self._run(
                stranded_helpers_command(project), timeout=_HELPER_CLEANUP_TIMEOUT
            )
            if listed.returncode != 0:
                return ["failed to list stranded helper containers"]
            failures = []
            for native_id in (line.strip() for line in listed.stdout.splitlines()):
                if not native_id:
                    continue
                removed = self._run(
                    remove_container_command(native_id),
                    timeout=_HELPER_CLEANUP_TIMEOUT,
                )
                if removed.returncode != 0:
                    failures.append("failed to remove a stranded helper container")
            return failures
        except (BackendTimeoutError, OSError):
            return ["failed to list stranded helper containers"]
