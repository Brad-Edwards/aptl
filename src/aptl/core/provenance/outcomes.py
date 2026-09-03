"""The closed outcome vocabulary for provenance collection (REP-003 / #452).

A provider reports one of a small, code-owned set of statuses. Missing,
denied, unsupported, truncated, timed-out and failed sources become explicit
:class:`ProvenanceLimitation` values carrying stable reason codes — never an
empty string, an empty map, an absent key, a guessed version, or a fabricated
digest.

This vocabulary is deliberately SEPARATE from
:class:`aptl.core.evidence.outcomes.CollectorStatus`. Capture statuses encode
evidence-acquisition semantics (mid-run loss, clock skew, finalization) that
do not apply to reading an apparatus manifest or a rule file, and the preflight
forbids reusing capture-specific types where their semantics do not fit.

REP-003 supplies facts and stable reason codes. It does NOT decide which
limitations are fatal — issue #472 owns readiness policy — and it does not
seal (issue #444).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

#: A provider id is a code-owned, non-executable slug. It is never an import
#: path, command, URL, host path, credential selector, or caller-supplied
#: factory name.
_PROVIDER_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")

#: Safe detail strings are short and drawn from the coordinator's own
#: vocabulary. Anything else (notably a raw exception string, which can carry
#: a host path, command, or secret) is dropped in favour of this.
_REDACTED_DETAIL = "detail withheld"
_MAX_DETAIL_LEN = 120

#: The details the coordinator and providers may attach. Naming them once
#: keeps the vocabulary in a single place and lets both layers share it.
DETAIL_ABSENT = "source not present"
DETAIL_UNREADABLE = "source not readable"
DETAIL_UNSUPPORTED = "source not supported"
DETAIL_OWNER_FAILURE = "owner reported failure"
DETAIL_ENTRY_LIMIT = "entry limit reached"
DETAIL_BYTE_LIMIT = "byte limit reached"
DETAIL_DEADLINE = "deadline exceeded"
DETAIL_CONTAINMENT = "path containment rejected"

#: Restricting to an allowlist is what keeps `str(exc)`, backend stderr, and
#: hostile metadata out of the record — filtering afterwards would be the
#: pattern this design rejects.
_SAFE_DETAILS = frozenset(
    {
        "",
        DETAIL_BYTE_LIMIT,
        DETAIL_ENTRY_LIMIT,
        DETAIL_DEADLINE,
        DETAIL_ABSENT,
        DETAIL_UNREADABLE,
        DETAIL_UNSUPPORTED,
        DETAIL_OWNER_FAILURE,
        DETAIL_CONTAINMENT,
    }
)


class ProvenanceOutcomeError(ValueError):
    """Raised when an outcome is constructed with a hostile or contradictory input."""


class ProvenanceStatus(str, Enum):
    """The closed status one provider invocation may report."""

    #: The declared source was read completely and within every limit.
    COLLECTED = "collected"
    #: The source does not exist in this realization (for example, a component
    #: that this profile did not deploy).
    UNAVAILABLE = "unavailable"
    #: The source exists but access was refused (permissions, policy).
    DENIED = "denied"
    #: The source exists but this build cannot interpret it.
    UNSUPPORTED = "unsupported"
    #: The provider exceeded its declared deadline.
    TIMED_OUT = "timed-out"
    #: The source exceeded a declared byte/entry limit; what was retained is
    #: disclosed, and this is NOT a success.
    TRUNCATED = "truncated"
    #: The owner adapter raised or returned an error.
    FAILED = "failed"


#: Only a complete collection is a success. TRUNCATED is deliberately excluded:
#: partial content that silently counted as success is exactly the degradation
#: REP-003 must disclose.
SUCCESS_STATUSES: frozenset[ProvenanceStatus] = frozenset({ProvenanceStatus.COLLECTED})

_REASON_CODES: dict[ProvenanceStatus, str] = {
    ProvenanceStatus.UNAVAILABLE: "aptl.run-provenance.source-unavailable",
    ProvenanceStatus.DENIED: "aptl.run-provenance.source-denied",
    ProvenanceStatus.UNSUPPORTED: "aptl.run-provenance.source-unsupported",
    ProvenanceStatus.TIMED_OUT: "aptl.run-provenance.source-timed-out",
    ProvenanceStatus.TRUNCATED: "aptl.run-provenance.source-truncated",
    ProvenanceStatus.FAILED: "aptl.run-provenance.source-failed",
}


def reason_code_for(status: ProvenanceStatus) -> str:
    """Return the stable reason code for a non-success ``status``.

    A success has nothing to explain, so asking for its code is a caller bug
    rather than a silently empty string.
    """
    try:
        return _REASON_CODES[status]
    except KeyError:
        raise ProvenanceOutcomeError("a successful status has no reason code") from None


def validate_provider_id(value: str) -> str:
    """Return ``value`` when it is a safe non-executable provider id, else raise."""
    if not isinstance(value, str) or _PROVIDER_ID_RE.fullmatch(value) is None:
        raise ProvenanceOutcomeError("provider_id is not a safe code-owned slug")
    return value


def _safe_detail(detail: str) -> str:
    """Return ``detail`` when it is coordinator-owned vocabulary, else a placeholder.

    Allowlisting rather than scrubbing is deliberate: a raw exception string can
    embed a host path, command, or credential, and no regex pass over arbitrary
    text is a trustworthy substitute for never admitting it.
    """
    if not isinstance(detail, str) or len(detail) > _MAX_DETAIL_LEN:
        return _REDACTED_DETAIL
    return detail if detail in _SAFE_DETAILS else _REDACTED_DETAIL


@dataclass(frozen=True, order=True)
class ProvenanceLimitation:
    """One declared limitation: a source that did not fully collect.

    Carries only stable identity and codes. Ordering is field order
    (``provider_id`` first) so a record's limitations serialize deterministically.
    """

    provider_id: str
    status: ProvenanceStatus
    reason_code: str
    detail: str

    def projection(self) -> dict[str, str]:
        """Return the canonical-JSON-ready projection of this limitation."""
        return {
            "provider_id": self.provider_id,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "detail": self.detail,
        }


def limitation_for(
    provider_id: str, status: ProvenanceStatus, *, detail: str = ""
) -> ProvenanceLimitation:
    """Build the limitation for a non-success provider outcome."""
    safe_id = validate_provider_id(provider_id)
    if status in SUCCESS_STATUSES:
        raise ProvenanceOutcomeError("a collected source does not declare a limitation")
    return ProvenanceLimitation(
        provider_id=safe_id,
        status=status,
        reason_code=reason_code_for(status),
        detail=_safe_detail(detail),
    )
