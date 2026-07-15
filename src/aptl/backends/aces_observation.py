"""Backend-observed realization state for the SEM-218 runtime gate (issue #578).

The SEM-218 non-approximation gate compares the value an author *declared* for a
realization concern against the value the backend *realized*, reading the latter
out of the snapshot the backend returns. APTL used to build that snapshot by
copying each planned resource's payload verbatim and marking it ``ready``, which
made the gate compare the plan against itself: it could never reject anything,
and a node the backend silently failed to start was still reported realized.

This module supplies the other half — what the deployment backend can actually
be *seen* to have done — so the snapshot records reality:

* a **node** is realized when its container is running (its ``os_family`` is read
  from the container's platform, so a linux-declared node backed by a windows
  container is caught);
* a **switch** node compiles to a network resource and is realized when the
  network exists;
* a resource the backend did not realize gets **no snapshot entry at all**, which
  is what the gate needs: an EXACT concern whose value is absent from the
  returned snapshot is a silent approximation and is rejected. Absence is the
  finding, not a gap to paper over.

The concern registry is imported from ACES rather than restated, so APTL cannot
drift from the set of concerns the gate actually enforces.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aces_contracts.planning import ProvisioningPlan
from aces_processor.semantics.realization import CONCERN_PAYLOAD_PATH

from aptl.backends.aces_realization_model import AptlRealization
from aptl.core.deployment._compose_realization_networks import _match_managed_network
from aptl.core.deployment._compose_service_health import (
    container_health,
    container_running,
)
from aptl.core.deployment.errors import BackendSeedError, BackendTimeoutError
from aptl.utils.logging import get_logger

if TYPE_CHECKING:
    from aptl.core.deployment.backend import DeploymentBackend
    from aptl.core.deployment.realization import DeploymentContentRealization

# Compose defaults the project name to "aptl"; a backend that scopes to a
# different project exposes its own ``project_name``.
_DEFAULT_PROJECT_NAME = "aptl"

log = get_logger("realization-observe")

# ACES node vocabulary for the two things APTL can realize. A VM node becomes a
# container; a switch node compiles to a network resource and becomes a Docker
# network. These are what APTL *realized*, reported only once the corresponding
# object is observed to exist — never read back off the plan.
_REALIZED_NODE_TYPE = "vm"
_REALIZED_SWITCH_TYPE = "switch"

_NODE_TYPE_PATH = CONCERN_PAYLOAD_PATH["node-type"]
_OS_FAMILY_PATH = CONCERN_PAYLOAD_PATH["os-family"]
_CONTENT_TYPE_PATH = CONCERN_PAYLOAD_PATH["content-type"]


@dataclass(frozen=True)
class ObservedResource(object):
    """What the deployment backend was observed to have realized for one address.

    ``concerns`` maps a SEM-218 concern payload path to the value the backend
    actually realized there. A concern the backend cannot be seen to have
    realized is simply absent, so the gate sees an omission rather than an echo.
    """

    realized: bool
    concerns: dict[tuple[str, ...], object] = field(default_factory=dict)


def observe_realization(
    backend: "DeploymentBackend",
    realization: AptlRealization,
    plan: ProvisioningPlan,
) -> dict[str, ObservedResource]:
    """Return, per planned address, what the backend actually realized."""

    observations: dict[str, ObservedResource] = {}
    node_containers = {
        node.address: node.container_name
        for node in realization.nodes
        if node.container_name
    }
    network_names = {network.address: network.name for network in realization.networks}
    placement_targets = {
        placement.address: placement.target_address
        for placement in realization.placements
    }
    placement_content = {
        placement.address: placement.content
        for placement in realization.placements
        if placement.content is not None
    }
    project_name = getattr(backend, "project_name", _DEFAULT_PROJECT_NAME)
    realized_networks = _realized_network_names(backend, project_name)

    for address, resource in plan.resources.items():
        if resource.resource_type == "node":
            observations[address] = _observe_node(
                backend, node_containers.get(address)
            )
        elif resource.resource_type == "network":
            observations[address] = _observe_network(
                network_names.get(address), realized_networks, project_name
            )
        else:
            observations[address] = _observe_placement(
                backend,
                node_containers,
                placement_targets.get(address),
                placement_content.get(address),
            )
    return observations


def _safe_inspect(backend: "DeploymentBackend", name: str) -> dict[str, Any]:
    """Inspect a project-owned container, treating uncertainty as "absent".

    A ``docker inspect`` that times out or errors leaves the container's state
    unknown, and an unobservable resource must fail closed — read as not
    realized — rather than either crashing the whole observation pass or being
    assumed realized. Absence is the safe reading: it drops the entry and lets
    the SEM-218 gate reject an EXACT concern it could not confirm.
    """

    try:
        if not backend.container_exists(name):
            return {}
        info = backend.container_inspect(name)
    except (BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not inspect project container %s (%s)",
            name,
            type(exc).__name__,
        )
        return {}
    return info if isinstance(info, dict) else {}


def _observe_node(
    backend: "DeploymentBackend",
    container_name: str | None,
) -> ObservedResource:
    """Observe one ACES node through the container the backend realized for it."""

    if not container_name:
        return ObservedResource(realized=False)
    info = _safe_inspect(backend, container_name)
    if not _container_realized(info):
        return ObservedResource(realized=False)

    concerns: dict[tuple[str, ...], object] = {
        _NODE_TYPE_PATH: _REALIZED_NODE_TYPE,
    }
    os_family = _observed_os_family(info)
    if os_family is not None:
        concerns[_OS_FAMILY_PATH] = os_family
    return ObservedResource(realized=True, concerns=concerns)


def _observe_network(
    network_name: str | None,
    realized_networks: set[str],
    project_name: str,
) -> ObservedResource:
    """Observe one ACES network, which is how a switch node gets realized."""

    if not network_name or not _network_realized(
        network_name, realized_networks, project_name
    ):
        return ObservedResource(realized=False)
    return ObservedResource(
        realized=True,
        concerns={_NODE_TYPE_PATH: _REALIZED_SWITCH_TYPE},
    )


def _observe_placement(
    backend: "DeploymentBackend",
    node_containers: dict[str, str],
    target_address: str | None,
    content: "DeploymentContentRealization | None",
) -> ObservedResource:
    """Observe a node-scoped placement through the node that received it.

    A content or account placement is realized into a node's container, so the
    container running and settled *is* the observable that the placement landed
    somewhere real. A placement whose target node never came up — or came up
    unhealthy — is not realized. ``target_address`` is the node address the real
    placement resolver already resolved for this placement (content, account, or
    feature binding), so this does not re-derive it from the raw payload.
    """

    container_name = node_containers.get(target_address) if target_address else None
    if not container_name:
        return ObservedResource(realized=False)
    if not _container_realized(_safe_inspect(backend, container_name)):
        return ObservedResource(realized=False)

    concerns: dict[tuple[str, ...], object] = {}
    content_type = _observed_content_type(backend, content)
    if content_type is not None:
        concerns[_CONTENT_TYPE_PATH] = content_type
    return ObservedResource(realized=True, concerns=concerns)


def _container_realized(info: Mapping[str, Any]) -> bool:
    """Return whether an inspected container is running and, if checked, healthy."""

    if not info or not container_running(info):
        return False
    health = container_health(info)
    return not health or health == "healthy"


def _observed_content_type(
    backend: "DeploymentBackend",
    content: "DeploymentContentRealization | None",
) -> str | None:
    """Return the destination kind observed by the deployment provider."""

    if content is None:
        return None
    try:
        observed = backend.observe_content_type(content)
    except (BackendSeedError, BackendTimeoutError, OSError) as exc:
        log.warning(
            "could not observe content type for %s (%s)",
            content.address,
            type(exc).__name__,
        )
        return None
    return observed if observed in ("file", "directory") else None


def _observed_os_family(info: Mapping[str, Any]) -> str | None:
    """Return the OS family the container actually runs, per ``docker inspect``.

    Docker reports the container's platform (``linux`` / ``windows``), which is
    the same vocabulary ACES uses for ``os_family``. When the daemon reports no
    platform we return ``None`` rather than guessing: an unobservable EXACT
    concern must be rejected, not assumed honoured.
    """

    platform = info.get("Platform")
    if isinstance(platform, str) and platform.strip():
        return platform.strip().lower()
    return None


def _realized_network_names(
    backend: "DeploymentBackend",
    project_name: str,
) -> set[str]:
    """Return the project's realized Docker networks.

    Scopes to this compose project's networks (``host_list_lab_networks``) rather
    than every network on the daemon, so an unrelated tenant's ``aptl-*`` network
    on a shared host is never mistaken for a realization of ours.
    """

    try:
        names = backend.host_list_lab_networks(project_name)
    except (BackendTimeoutError, OSError) as exc:
        log.warning("could not list realized networks (%s)", type(exc).__name__)
        return set()
    return set(names) if isinstance(names, list | tuple | set) else set()


def _network_realized(
    network_name: str,
    realized: set[str],
    project_name: str,
) -> bool:
    """Return whether a scenario network exists among the realized ones.

    Compose materializes a declared network under one of several project-scoped
    names (``<project>_aptl-<stem>``, ``aptl-<stem>``, …). This reuses the same
    candidate matcher the network-creation path uses (``_match_managed_network``)
    rather than guessing the delimiter, so the observed name is recognized the
    same way it was written — the mismatch a bespoke suffix check would miss.
    """

    return _match_managed_network(network_name, realized, project_name) is not None
