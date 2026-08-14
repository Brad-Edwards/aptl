"""Provider-neutral deployment-serving interaction contract (ADR-053).

The seam assigns already-admitted component addresses to APTL's finite
operator groups. It cannot add, remove, configure, or materialize components.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from aptl.backends.identity import BackendIdentity
from aptl.core.scenario_bundle import PackIdentity

ENTRY_POINT_GROUP = "aptl.pack_backend_interactions"
EXTENSION_API_VERSION = "1"


@dataclass(frozen=True, order=True)
class ComponentGroupMembership:
    """One exact admitted component address and its operator groups."""

    component_address: str
    groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class PackBackendInteractionContext:
    """The immutable, realization-free context visible to a provider."""

    pack: PackIdentity
    backend: BackendIdentity
    component_addresses: tuple[str, ...]
    operator_groups: tuple[str, ...]


@dataclass(frozen=True)
class PackBackendInteractionResult:
    """The only provider result: a total address-to-group membership relation."""

    memberships: tuple[ComponentGroupMembership, ...]


class PackBackendInteractionProvider(Protocol):
    """Installed provider contract; installation grants normal Python authority."""

    provider_id: str
    extension_api_version: str
    supported_pack_id: str
    supported_pack_versions: tuple[str, ...]
    supported_pack_set_digests: tuple[str, ...]
    backend_target_name: str
    backend_target_versions: tuple[str, ...]
    backend_profiles: tuple[str, ...]
    backend_transports: tuple[str, ...]

    def resolve(
        self, context: PackBackendInteractionContext
    ) -> PackBackendInteractionResult: ...


@dataclass(frozen=True)
class ResolvedPackBackendInteraction:
    """Core-owned, validated copy of one provider resolution."""

    memberships: tuple[ComponentGroupMembership, ...]
    mapping_digest: str
    provider_id: str
    extension_api_version: str
    distribution: str = ""
    distribution_version: str = ""
    entry_point: str = ""

    def groups_for(self, component_address: str) -> tuple[str, ...]:
        """Return the exact groups assigned to an admitted component."""

        for membership in self.memberships:
            if membership.component_address == component_address:
                return membership.groups
        raise KeyError(component_address)

    def evidence(self) -> dict[str, str]:
        """Return bounded host-observed provider and mapping evidence."""

        return {
            "provider_id": self.provider_id,
            "extension_api_version": self.extension_api_version,
            "distribution": self.distribution,
            "distribution_version": self.distribution_version,
            "entry_point": self.entry_point,
            "mapping_digest": self.mapping_digest,
        }


__all__ = [
    "ENTRY_POINT_GROUP",
    "EXTENSION_API_VERSION",
    "ComponentGroupMembership",
    "PackBackendInteractionContext",
    "PackBackendInteractionProvider",
    "PackBackendInteractionResult",
    "ResolvedPackBackendInteraction",
]
