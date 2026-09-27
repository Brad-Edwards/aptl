"""Provider readback helpers for realized scenario networks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aptl.core.deployment._compose_realization_networks import _match_managed_network
from aptl.core.deployment.errors import BackendTimeoutError
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend

log = get_logger("realization-observe")


def realized_network_names(
    backend: DeploymentBackend,
    project_name: str,
) -> set[str]:
    """Return only the current Compose project's realized Docker networks."""

    try:
        names = backend.host_list_lab_networks(project_name)
    except (BackendTimeoutError, OSError) as exc:
        log.warning("could not list realized networks (%s)", type(exc).__name__)
        return set()
    return set(names) if isinstance(names, list | tuple | set) else set()


def network_realized(
    network_name: str,
    realized: set[str],
    project_name: str,
) -> bool:
    """Return whether a managed scenario network exists in provider readback."""

    return _match_managed_network(network_name, realized, project_name) is not None


__all__ = ("network_realized", "realized_network_names")
