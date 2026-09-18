"""Project-scoped residual container cleanup for Compose backends."""

from __future__ import annotations

from typing import Protocol


class _CleanupBackend(Protocol):
    """Backend surface required by the project-container cleanup helper."""

    _project_name: str

    def _remove_owned_containers(self, managed_by: str) -> list[str]:
        """Remove only freshly verified receipt-owned native container IDs."""

        ...


class ComposeProjectCleanupMixin(object):
    """Remove project-owned containers that Compose may leave behind."""

    def remove_generic_materializer_containers(self) -> list[str]:
        """Force-remove containers realized directly by the generic materializer."""

        return self._remove_owned_containers("direct")

    def remove_project_containers(self) -> list[str]:
        """Force-remove residual containers carrying the Compose project identity."""

        return self._remove_owned_containers("compose")
