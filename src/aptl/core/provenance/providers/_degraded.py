"""The internal degradation signal shared by the built-in providers (#452).

A provider's collection either produces content or stops for a declared
reason. Expressing "stop with this reason" as a raised signal — rather than an
early ``return`` at each check — keeps every ``collect()`` to one success path
plus one handler, so the reason vocabulary stays in one place and the read
order of the checks is obvious.

This is deliberately NOT a public exception hierarchy (the architecture
preflight forbids adding one). It is a single module-private control-flow
signal that never escapes its provider: each ``collect()`` catches it and
converts it into a typed :class:`~aptl.core.provenance.protocol.
ProvenanceResult`, exactly as the coordinator would have done for an early
return.
"""

from __future__ import annotations

from collections.abc import Mapping

from aptl.core.provenance.outcomes import (
    DETAIL_ABSENT,
    DETAIL_BYTE_LIMIT,
    DETAIL_DEADLINE,
    DETAIL_ENTRY_LIMIT,
    DETAIL_OWNER_FAILURE,
    DETAIL_UNREADABLE,
    ProvenanceStatus,
)
from aptl.core.provenance.protocol import ProvenanceResult

# The detail strings come from the shared vocabulary in ``outcomes``: a raw
# exception string — which can carry a host path, command, or credential — can
# never take their place.


class ProviderDegraded(Exception):
    """Internal signal: this provider cannot complete, with a declared reason."""

    def __init__(
        self,
        status: ProvenanceStatus,
        detail: str = "",
        payload: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.payload = dict(payload or {})

    def as_result(self, provider_id: str) -> ProvenanceResult:
        """Convert this signal into the provider's typed result.

        Content gathered before the signal is deliberately dropped: partial
        content is not evidence of the apparatus, and reporting it alongside a
        degraded status would invite a reader to treat it as complete.
        """
        return ProvenanceResult(
            provider_id=provider_id,
            status=self.status,
            payload=self.payload,
            detail=self.detail,
        )


def absent(payload: Mapping[str, object] | None = None) -> ProviderDegraded:
    """Return the signal for a source that does not exist in this realization."""
    return ProviderDegraded(ProvenanceStatus.UNAVAILABLE, DETAIL_ABSENT, payload)


def owner_failure(payload: Mapping[str, object] | None = None) -> ProviderDegraded:
    """Return the signal for an owner adapter that raised or returned an error."""
    return ProviderDegraded(ProvenanceStatus.FAILED, DETAIL_OWNER_FAILURE, payload)


def entry_limit(payload: Mapping[str, object] | None = None) -> ProviderDegraded:
    """Return the signal for exceeding the declared entry budget."""
    return ProviderDegraded(ProvenanceStatus.TRUNCATED, DETAIL_ENTRY_LIMIT, payload)


def byte_limit(payload: Mapping[str, object] | None = None) -> ProviderDegraded:
    """Return the signal for exceeding the declared byte budget."""
    return ProviderDegraded(ProvenanceStatus.TRUNCATED, DETAIL_BYTE_LIMIT, payload)


def deadline(payload: Mapping[str, object] | None = None) -> ProviderDegraded:
    """Return the signal for exceeding the declared deadline."""
    return ProviderDegraded(ProvenanceStatus.TIMED_OUT, DETAIL_DEADLINE, payload)


def denied(payload: Mapping[str, object] | None = None) -> ProviderDegraded:
    """Return the signal for a source that exists but could not be read."""
    return ProviderDegraded(ProvenanceStatus.DENIED, DETAIL_UNREADABLE, payload)
