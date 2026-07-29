"""Host-inventory slice of the deployment backend Protocol (CLI-004 / ADR-023).

Split out of :mod:`aptl.core.deployment.backend` so the full
``DeploymentBackend`` interface stays within one file's size budget while
remaining a single structural type: ``DeploymentBackend`` inherits this
Protocol, so an implementation still satisfies one interface and callers still
see one type.

These return parsed host-level information instead of exposing a generic argv
passthrough. Future non-Docker backends implement them in their own terms;
today both backends back them with the docker CLI but the Protocol stays
Docker-shape-agnostic.
"""

from typing import Any, Protocol


class HostInventoryBackend(Protocol):
    """Host-level inventory operations a deployment backend exposes."""

    def host_versions(self) -> dict[str, str]:
        """Return parsed daemon-side software versions.

        Returns:
            Dict with keys ``docker`` and ``compose``. Each value is the
            version string as reported by the daemon, or empty string
            on probe failure (missing binary, daemon down, etc.).
        """
        ...

    def host_list_lab_containers(self) -> list[dict[str, Any]]:
        """Enumerate ``aptl-*`` containers visible to the daemon.

        Each row carries ``name``, ``image``, ``id``, ``status``,
        ``labels`` (dict), and ``ports`` (list of port-mapping strings).
        Catches containers outside the current compose project that
        nevertheless follow the lab's naming convention.
        """
        ...

    def host_list_lab_networks(self, name_prefix: str) -> list[str]:
        """List network names whose names start with ``name_prefix``."""
        ...

    def host_list_networks(self) -> list[str]:
        """List every network name visible to the deployment backend."""
        ...

    def host_inspect_network(self, name: str) -> dict[str, Any]:
        """Return parsed network metadata.

        Returns:
            Dict with keys ``name``, ``subnet``, ``gateway``,
            ``containers`` (sorted list of attached container names).
            Empty dict on any failure.
        """
        ...
