"""The code-owned provenance provider registry (REP-003 / issue #452).

This is the narrow, trusted capability-declaration seam the preflight
requires: one internal coordinator over code-owned registrations, NOT one
monolithic collector and NOT a general plugin framework.

A registration pins a stable provider id, implementation version, the
capability/source it supplies, the owner adapter it needs, its applicable seal
point, its requiredness policy key, and hard count/byte/time limits. The id is
a non-executable slug — never an import path, command, URL, host path,
credential selector, or user-controlled factory — so nothing in a record or a
policy file can steer collection at code.

The declaration pattern deliberately mirrors the incumbent
:class:`aptl.core.experiment.capture_registry.CollectorRegistration`:
``declaration_projection()`` emits canonical-JSON-ready data with sets sorted,
and ``effective_config_digest()`` pins the exact capability version a run
collected under, so a later reader can tell that a provider's declaration
changed.

The extension parameter is this registration set plus a :class:`SealProfile`
(seal point and policy-required provider ids). Adding the next built-in source
costs one registration, one narrow owner adapter, and its tests — no edit to
the aggregate record builder, run controller, RAES DTOs, storage layout, or
exporter. Dynamic imports and out-of-process third-party providers need a
separate authorization and sandboxing design and are out of scope here.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from aptl.core.provenance.identity import derive_identity
from aptl.core.provenance.outcomes import ProvenanceOutcomeError, validate_provider_id

#: Versioned identity of the registration declaration shape itself. A change to
#: which fields a declaration carries, or how its digest is computed, bumps
#: this so a persisted record states which registry shape produced it.
REGISTRY_SCHEMA_VERSION = "aptl-provenance-registry/v1"

#: Identity domain for a registration declaration.
_REGISTRATION_DOMAIN = "provider"

#: Identity domain for the aggregate registry declaration.
_REGISTRY_DOMAIN = "registry"


class ProvenanceRegistrationError(ValueError):
    """Raised when a registration, registry, or seal profile is not admissible."""


class SealPoint(str, Enum):
    """The boundary at which a provider's source is meaningful.

    Both members describe *ready-to-seal* collection. Issue #444 owns the
    actual seal; nothing here claims a run is sealed.
    """

    #: Facts about the run as a whole (apparatus, config identity, images).
    RUN_READY_TO_SEAL = "run-ready-to-seal"
    #: Facts scoped to one planned trial (scenario snapshot, capture bindings).
    TRIAL_READY_TO_SEAL = "trial-ready-to-seal"


@dataclass(frozen=True)
class ProvenanceLimits:
    """The hard bounds one provider is admitted under.

    The coordinator enforces these while collecting, so a pathological or
    hostile source cannot turn provenance into unbounded memory use or an
    unbounded stall.
    """

    max_bytes: int
    max_entries: int
    timeout_s: int


@dataclass(frozen=True)
class ProvenanceProviderRegistration:
    """One trusted, code-owned provider's static capability declaration.

    This is the whole capability surface the coordinator and the seal profile
    read. It carries NO factory, import path, or executable reference — the
    trusted adapter wiring is composed separately, exactly as the incumbent
    capture registry composes its collectors.
    """

    provider_id: str
    implementation_version: str
    provenance_kind: str
    owner_adapter: str
    seal_point: SealPoint
    requiredness_policy_key: str
    limits: ProvenanceLimits

    def __post_init__(self) -> None:
        """Validate the id is a safe slug and every declared limit is positive."""
        try:
            validate_provider_id(self.provider_id)
        except ProvenanceOutcomeError as exc:
            raise ProvenanceRegistrationError(str(exc)) from exc
        if not self.implementation_version or not self.provenance_kind:
            raise ProvenanceRegistrationError(
                "a registration must declare an implementation version and provenance kind"
            )
        limits = self.limits
        if limits.max_bytes <= 0 or limits.max_entries <= 0 or limits.timeout_s <= 0:
            raise ProvenanceRegistrationError("provenance limits must all be positive")

    def declaration_projection(self) -> dict[str, object]:
        """Return the canonical-JSON-ready projection of this declaration."""
        return {
            "registry_schema": REGISTRY_SCHEMA_VERSION,
            "provider_id": self.provider_id,
            "implementation_version": self.implementation_version,
            "provenance_kind": self.provenance_kind,
            "owner_adapter": self.owner_adapter,
            "seal_point": self.seal_point.value,
            "requiredness_policy_key": self.requiredness_policy_key,
            "max_bytes": self.limits.max_bytes,
            "max_entries": self.limits.max_entries,
            "timeout_s": self.limits.timeout_s,
        }

    def effective_config_digest(self) -> str:
        """Return the domain-separated canonical digest of this declaration."""
        return derive_identity(_REGISTRATION_DOMAIN, self.declaration_projection())


@dataclass(frozen=True)
class ProvenanceProviderRegistry:
    """An immutable set of trusted provider registrations, keyed by id."""

    registrations: tuple[ProvenanceProviderRegistration, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicate provider ids at construction."""
        ids = [registration.provider_id for registration in self.registrations]
        if len(set(ids)) != len(ids):
            raise ProvenanceRegistrationError(
                "ProvenanceProviderRegistry contains duplicate provider IDs"
            )

    def ordered(self) -> tuple[ProvenanceProviderRegistration, ...]:
        """Return registrations in deterministic id-sorted order.

        Collection order must never affect a computed identity, so the
        coordinator always walks this ordering rather than construction order.
        """
        return tuple(sorted(self.registrations, key=lambda item: item.provider_id))

    def get(self, provider_id: str) -> ProvenanceProviderRegistration | None:
        """Return the registration for ``provider_id``, or ``None``."""
        for registration in self.registrations:
            if registration.provider_id == provider_id:
                return registration
        return None

    def for_seal_point(self, seal_point: SealPoint) -> tuple[ProvenanceProviderRegistration, ...]:
        """Return the id-sorted registrations applicable at ``seal_point``."""
        return tuple(item for item in self.ordered() if item.seal_point is seal_point)

    def declaration_digest(self) -> str:
        """Return the aggregate canonical digest of every registration declaration."""
        return derive_identity(
            _REGISTRY_DOMAIN,
            {"registrations": [item.declaration_projection() for item in self.ordered()]},
        )


@dataclass(frozen=True)
class SealProfile:
    """The seal point plus the provider ids a policy requires there.

    This is the extension parameter for the seam. REP-003 validates that a
    required provider actually exists and reports its outcome; deciding which
    outcomes are fatal belongs to the readiness policy in issue #472.
    """

    seal_point: SealPoint
    required_provider_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Reject a hostile required id before it can reach a lookup or a record."""
        for provider_id in self.required_provider_ids:
            try:
                validate_provider_id(provider_id)
            except ProvenanceOutcomeError as exc:
                raise ProvenanceRegistrationError(str(exc)) from exc

    def requires(self, provider_id: str) -> bool:
        """Return whether ``provider_id`` is policy-required at this seal point."""
        return provider_id in self.required_provider_ids

    def validate_against(self, registry: ProvenanceProviderRegistry) -> None:
        """Raise when a required provider id has no registration.

        Fails closed: a policy that names a provider nobody implements would
        otherwise silently report ready-to-seal with that source missing.
        """
        missing = sorted(
            provider_id
            for provider_id in self.required_provider_ids
            if registry.get(provider_id) is None
        )
        if missing:
            raise ProvenanceRegistrationError(
                "seal profile requires provider IDs that are not registered"
            )


def build_registry(
    registrations: Iterable[ProvenanceProviderRegistration],
) -> ProvenanceProviderRegistry:
    """Return an immutable registry over ``registrations``."""
    items: Sequence[ProvenanceProviderRegistration] = tuple(registrations)
    return ProvenanceProviderRegistry(tuple(items))
