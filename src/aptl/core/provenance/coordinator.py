"""The bounded provenance-collection coordinator (REP-003 / issue #452).

The coordinator owns everything a provider must not: deadline enforcement,
limit enforcement, exception normalization, secret-invariant checking,
canonical identity, and deterministic ordering. A provider only reports its
declared source.

Every internal failure collapses into the small
:class:`~aptl.core.provenance.outcomes.ProvenanceStatus` vocabulary. A raising
provider, an over-deadline provider, an over-quota provider, an unregistered
provider, a provider claiming another's id, and a provider returning
secret-shaped or unserializable content all become explicit typed results with
stable reason codes — never a silent skip, an empty section, or a fabricated
digest.

A non-collected provider contributes NO content identity. Recording a digest
for a source that failed would be exactly the fabricated-identity failure mode
the requirement prohibits.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from aptl.core.provenance.identity import (
    ProvenanceIdentityError,
    ProvenanceLeaf,
    derive_identity,
    family_identity,
)
from aptl.core.provenance.outcomes import (
    DETAIL_ABSENT,
    DETAIL_DEADLINE,
    DETAIL_ENTRY_LIMIT,
    DETAIL_OWNER_FAILURE,
    DETAIL_UNSUPPORTED,
    SUCCESS_STATUSES,
    ProvenanceLimitation,
    ProvenanceStatus,
    limitation_for,
)
from aptl.core.provenance.protocol import (
    MonotonicClock,
    ProvenanceContext,
    ProvenanceProvider,
    ProvenanceResult,
)
from aptl.core.provenance.registry import (
    ProvenanceLimits,
    ProvenanceProviderRegistration,
    ProvenanceProviderRegistry,
    SealProfile,
)
from aptl.utils.redaction import redact

log = logging.getLogger(__name__)

#: Identity domain for one provider section's content.
_SECTION_DOMAIN = "section"

#: Identity domain for the aggregate over every section.
_AGGREGATE_DOMAIN = "collection"

#: Schema identity of the collection projection shape.
COLLECTION_SCHEMA_VERSION = "aptl-run-provenance-collection/v1"

#: Hard ceilings applied to a payload regardless of what a provider declares,
#: so a bug in one registration cannot admit unbounded record content.
_MAX_PAYLOAD_KEYS = 64
_MAX_PAYLOAD_DEPTH = 6
_MAX_PAYLOAD_STRING = 4096

#: Placeholder limits used only to satisfy the registration invariant while an
#: UNSUPPORTED section is built for a provider that has no registration. Such a
#: provider is never invoked, so these bounds are never enforced against real
#: collection.
_UNREGISTERED_LIMITS = ProvenanceLimits(max_bytes=1, max_entries=1, timeout_s=1)


@dataclass(frozen=True)
class ProvenanceSection:
    """One provider's contribution to the run provenance record.

    ``content_identity`` is ``None`` for anything other than a full
    collection: a failed, denied, truncated, or timed-out source has no
    trustworthy content identity, and inventing one would misrepresent the
    apparatus.
    """

    provider_id: str
    status: ProvenanceStatus
    declaration_digest: str
    content_identity: str | None = None
    payload: Mapping[str, object] = field(default_factory=dict)
    leaf_count: int = 0

    def projection(self) -> dict[str, object]:
        """Return the canonical-JSON-ready projection of this section."""
        return {
            "provider_id": self.provider_id,
            "status": self.status.value,
            "declaration_digest": self.declaration_digest,
            "content_identity": self.content_identity,
            "payload": dict(self.payload),
            "leaf_count": self.leaf_count,
        }


@dataclass(frozen=True)
class ProvenanceCollection:
    """The one-shot result of collecting every applicable provider."""

    sections: Mapping[str, ProvenanceSection]
    limitations: tuple[ProvenanceLimitation, ...]
    aggregate_identity: str
    registry_declaration_digest: str

    def projection(self) -> dict[str, object]:
        """Return the deterministic canonical-JSON-ready projection."""
        return {
            "schema_version": COLLECTION_SCHEMA_VERSION,
            "registry_declaration_digest": self.registry_declaration_digest,
            "aggregate_identity": self.aggregate_identity,
            "sections": [
                self.sections[provider_id].projection() for provider_id in sorted(self.sections)
            ],
            "limitations": [item.projection() for item in sorted(self.limitations)],
        }


def _mapping_is_bounded(value: Mapping[object, object], depth: int) -> bool:
    """Return whether a mapping's size, keys, and values are all within bounds."""
    keys_bounded = all(
        isinstance(key, str) and len(key) <= _MAX_PAYLOAD_STRING for key in value
    )
    return (
        len(value) <= _MAX_PAYLOAD_KEYS
        and keys_bounded
        and all(_payload_is_bounded(item, depth + 1) for item in value.values())
    )


def _sequence_is_bounded(value: list | tuple, depth: int) -> bool:
    """Return whether a sequence's length and every item are within bounds."""
    return len(value) <= _MAX_PAYLOAD_KEYS and all(
        _payload_is_bounded(item, depth + 1) for item in value
    )


def _payload_is_bounded(value: object, depth: int = 0) -> bool:
    """Return whether ``value`` is within the hard structural ceilings."""
    if depth > _MAX_PAYLOAD_DEPTH:
        bounded = False
    elif isinstance(value, str):
        bounded = len(value) <= _MAX_PAYLOAD_STRING
    elif isinstance(value, Mapping):
        bounded = _mapping_is_bounded(value, depth)
    elif isinstance(value, (list, tuple)):
        bounded = _sequence_is_bounded(value, depth)
    else:
        bounded = isinstance(value, (int, float, bool)) or value is None
    return bounded


def _payload_is_safe(payload: Mapping[str, object]) -> bool:
    """Return whether ``payload`` is bounded, canonical, and secret-free.

    The shared redactor is reused as a DRIFT DETECTOR here, matching the
    runstore's create-once secret invariant: a payload the production
    classification policy would change never reaches a record. It is not
    permission for a provider to read a prohibited source in the first place —
    that is settled by allowlisting the source.
    """
    if not _payload_is_bounded(payload):
        return False
    try:
        snapshot = dict(payload)
        safe = redact(snapshot) == snapshot
        derive_identity(_SECTION_DOMAIN, {"payload": snapshot})
    except (TypeError, ValueError, RecursionError):
        safe = False
    return safe


def _degraded(
    registration: ProvenanceProviderRegistration,
    status: ProvenanceStatus,
    detail: str = "",
) -> tuple[ProvenanceSection, ProvenanceLimitation]:
    """Build the section + limitation pair for a non-collected source."""
    section = ProvenanceSection(
        provider_id=registration.provider_id,
        status=status,
        declaration_digest=registration.effective_config_digest(),
    )
    return section, limitation_for(registration.provider_id, status, detail=detail)


def _collected(
    registration: ProvenanceProviderRegistration, result: ProvenanceResult
) -> ProvenanceSection:
    """Build the section for a fully collected source."""
    leaves: Sequence[ProvenanceLeaf] = tuple(result.leaves)
    return ProvenanceSection(
        provider_id=registration.provider_id,
        status=ProvenanceStatus.COLLECTED,
        declaration_digest=registration.effective_config_digest(),
        content_identity=family_identity(_SECTION_DOMAIN, leaves),
        payload=dict(result.payload),
        leaf_count=len(leaves),
    )


def _rejection(
    registration: ProvenanceProviderRegistration,
    result: ProvenanceResult,
    elapsed: float,
) -> tuple[ProvenanceStatus, str] | None:
    """Return the first ``(status, detail)`` disqualifying ``result``, else ``None``.

    Ordered so the most fundamental violation wins: a result that impersonates
    another provider is a wiring fault, an overrun deadline invalidates whatever
    was gathered, and only then are quota and content validity considered.
    """
    impersonating = result.provider_id != registration.provider_id
    if impersonating:
        log.warning(
            "run-provenance: provider %s returned a result for another provider id",
            registration.provider_id,
        )
    unsafe_payload = not _payload_is_safe(result.payload)
    if unsafe_payload:
        log.warning(
            "run-provenance: provider %s payload rejected by the safety invariant",
            registration.provider_id,
        )
    checks = (
        (impersonating, ProvenanceStatus.FAILED, DETAIL_OWNER_FAILURE),
        (elapsed >= float(registration.limits.timeout_s), ProvenanceStatus.TIMED_OUT, DETAIL_DEADLINE),
        (result.status not in SUCCESS_STATUSES, result.status, result.detail),
        (
            len(result.leaves) > registration.limits.max_entries,
            ProvenanceStatus.TRUNCATED,
            DETAIL_ENTRY_LIMIT,
        ),
        (unsafe_payload, ProvenanceStatus.FAILED, DETAIL_OWNER_FAILURE),
    )
    for failed, status, detail in checks:
        if failed:
            return status, detail
    return None


def _evaluate(
    registration: ProvenanceProviderRegistration,
    result: ProvenanceResult,
    *,
    elapsed: float,
) -> tuple[ProvenanceSection, ProvenanceLimitation | None]:
    """Turn one raw provider result into a validated section (+ limitation)."""
    rejection = _rejection(registration, result, elapsed)
    if rejection is not None:
        return _degraded(registration, rejection[0], rejection[1])
    try:
        return _collected(registration, result), None
    except ProvenanceIdentityError:
        log.warning(
            "run-provenance: provider %s produced an invalid content identity",
            registration.provider_id,
        )
        return _degraded(registration, ProvenanceStatus.FAILED, DETAIL_OWNER_FAILURE)


def _invoke(
    provider: ProvenanceProvider,
    registration: ProvenanceProviderRegistration,
    monotonic: MonotonicClock,
) -> tuple[ProvenanceSection, ProvenanceLimitation | None]:
    """Run one provider under its declared limits, normalizing every failure."""
    started_at = monotonic()
    context = ProvenanceContext(
        registration=registration, clock=monotonic, started_at=started_at
    )
    try:
        result = provider.collect(context)
    except Exception:
        # The exception's text is deliberately not carried anywhere: it can
        # embed a host path, command, or credential. The provider id, stage,
        # and stable reason code are what a reader needs.
        log.warning(
            "run-provenance: provider %s raised during collection", registration.provider_id
        )
        return _degraded(registration, ProvenanceStatus.FAILED, DETAIL_OWNER_FAILURE)
    return _evaluate(registration, result, elapsed=monotonic() - started_at)


def collect_provenance(
    *,
    providers: Iterable[ProvenanceProvider],
    registry: ProvenanceProviderRegistry,
    profile: SealProfile,
    monotonic: MonotonicClock,
) -> ProvenanceCollection:
    """Collect every applicable provider into one deterministic result.

    ``providers`` is the composed trusted fleet; ``registry`` is the
    declaration authority. A provider without a registration is UNSUPPORTED
    rather than trusted, and a policy-required provider that never ran is
    recorded UNAVAILABLE rather than assumed absent-and-fine.
    """
    profile.validate_against(registry)

    sections: dict[str, ProvenanceSection] = {}
    limitations: list[ProvenanceLimitation] = []

    for provider in providers:
        provider_id = getattr(provider, "provider_id", "")
        registration = registry.get(provider_id)
        if registration is None:
            unregistered = ProvenanceProviderRegistration(
                provider_id=provider_id,
                implementation_version="unregistered",
                provenance_kind="unregistered",
                owner_adapter="unregistered",
                seal_point=profile.seal_point,
                requiredness_policy_key="unregistered",
                limits=_UNREGISTERED_LIMITS,
            )
            section, limitation = _degraded(
                unregistered, ProvenanceStatus.UNSUPPORTED, DETAIL_UNSUPPORTED
            )
        else:
            section, limitation = _invoke(provider, registration, monotonic)
        sections[section.provider_id] = section
        if limitation is not None:
            limitations.append(limitation)

    for registration in registry.for_seal_point(profile.seal_point):
        if registration.provider_id in sections:
            continue
        if not profile.requires(registration.provider_id):
            continue
        section, limitation = _degraded(
            registration, ProvenanceStatus.UNAVAILABLE, DETAIL_ABSENT
        )
        sections[section.provider_id] = section
        limitations.append(limitation)

    aggregate = derive_identity(
        _AGGREGATE_DOMAIN,
        {
            "sections": [
                {
                    "provider_id": provider_id,
                    "status": sections[provider_id].status.value,
                    "content_identity": sections[provider_id].content_identity,
                    "declaration_digest": sections[provider_id].declaration_digest,
                }
                for provider_id in sorted(sections)
            ]
        },
    )
    return ProvenanceCollection(
        sections=sections,
        limitations=tuple(sorted(limitations)),
        aggregate_identity=aggregate,
        registry_declaration_digest=registry.declaration_digest(),
    )
