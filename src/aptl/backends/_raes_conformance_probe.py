"""Detection and binding for RAES' backend-neutral live conformance probe.

RAES ships a generic ``provision.node.vm`` probe with no concrete service
source, so it maps to no APTL compose profile on its own. This module decides
whether a planned node *is* that probe and, when it is, binds it to one enabled
APTL service so the live conformance run has something real to exercise.

Split out of :mod:`aptl.backends.raes_realization` to keep that module within
its size budget. It depends only on lower-level helpers, never back on
``raes_realization``, so the import is one-directional.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from aptl.backends.raes_profiles import public_start_profiles
from aptl.backends.raes_realization_values import (
    mapping as _mapping,
    network_names as _network_names,
    service_names as _service_names,
    static_addresses as _static_addresses,
)

if TYPE_CHECKING:
    from raes_contracts.planning import PlannedResource

    from aptl.backends._compose_profile_index import ComposeProfileIndex
    from aptl.core.config import AptlConfig


def _is_raes_conformance_probe_node(
    resource: PlannedResource,
    payload: Mapping[str, Any],
) -> bool:
    """Return whether a node is RAES' backend-neutral live probe."""

    spec = _mapping(payload.get("spec"))
    node_spec = _mapping(spec.get("node")) if spec else None
    infra_spec = _mapping(spec.get("infrastructure")) if spec else None
    return (
        _has_raes_conformance_probe_identity(resource, payload)
        and _has_empty_raes_probe_node_spec(node_spec)
        and _has_empty_raes_probe_infra_spec(infra_spec)
    )


def _has_raes_conformance_probe_identity(
    resource: PlannedResource,
    payload: Mapping[str, Any],
) -> bool:
    """Return whether resource identity matches RAES' generic VM probe."""

    return (
        resource.address,
        str(payload.get("name", "")),
        str(payload.get("node_name", "")),
        str(payload.get("node_type", "")),
        str(payload.get("os_family", "")),
    ) == ("provision.node.vm", "vm", "vm", "vm", "linux")


def _has_empty_raes_probe_node_spec(
    node_spec: Mapping[str, Any] | None,
) -> bool:
    """Return whether the generic probe has no concrete service source."""

    return (
        bool(node_spec)
        and node_spec.get("source") is None
        and not _service_names(node_spec)
    )


def _has_empty_raes_probe_infra_spec(
    infra_spec: Mapping[str, Any] | None,
) -> bool:
    """Return whether the generic probe has no scenario network intent."""

    return not _network_names(infra_spec) and not _static_addresses(infra_spec)


def _conformance_probe_services(
    profile_index: ComposeProfileIndex,
    config: AptlConfig,
) -> frozenset[str]:
    """Bind RAES' generic probe to one enabled APTL service, if available."""

    for profile in public_start_profiles(config):
        for service_name, service in sorted(profile_index.services.items()):
            if profile in service.profiles:
                return frozenset({service_name})
    return frozenset()
