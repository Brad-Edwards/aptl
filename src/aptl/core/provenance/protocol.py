"""The narrow provider seam for run-scoped provenance (REP-003 / issue #452).

A provider is handed a :class:`ProvenanceContext` carrying only its own
registration, its deadline, and a monotonic clock — never a whole
:class:`~aptl.core.config.AptlConfig`, ``EnvVars``, a deployment backend, a
controller, or generic shell/HTTP/filesystem authority. Whatever narrow owner
adapter a provider needs is bound into the provider instance when the trusted
fleet is composed, exactly as the incumbent capture registry composes its
collectors separately from their declarations.

A provider returns a :class:`ProvenanceResult`: a closed status, sorted content
leaves, and a bounded owner-native payload. It does not persist, redact,
canonicalize, hash the aggregate, or decide readiness — the coordinator owns
all of that, and issue #472 owns which limitations are fatal.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from aptl.core.provenance.identity import ProvenanceLeaf
from aptl.core.provenance.outcomes import ProvenanceStatus
from aptl.core.provenance.registry import ProvenanceProviderRegistration


class MonotonicClock(Protocol):
    """A monotonic seconds source, injectable so deadlines are testable.

    Deliberately distinct from
    :class:`aptl.core.correlation.clock.ClockProvider`, which exists to
    DISCLOSE a source's wall-clock context. Deadlines need elapsed time, and
    conflating the two would put a wall-clock timestamp where a duration
    belongs.
    """

    def __call__(self) -> float: ...


@dataclass(frozen=True)
class ProvenanceContext:
    """The immutable context handed to one provider invocation."""

    registration: ProvenanceProviderRegistration
    clock: MonotonicClock
    started_at: float

    @property
    def deadline_seconds(self) -> float:
        """Return the provider's declared wall budget for this invocation."""
        return float(self.registration.limits.timeout_s)

    @property
    def max_bytes(self) -> int:
        """Return the provider's declared byte budget."""
        return self.registration.limits.max_bytes

    @property
    def max_entries(self) -> int:
        """Return the provider's declared entry budget."""
        return self.registration.limits.max_entries

    def expired(self) -> bool:
        """Return whether the declared deadline has already passed.

        Providers that iterate a source check this between entries so an
        over-long collection stops rather than being detected only afterwards.
        """
        return (self.clock() - self.started_at) >= self.deadline_seconds


@dataclass(frozen=True)
class ProvenanceResult:
    """One provider invocation's bounded, typed outcome.

    ``leaves`` are the content identities the provider observed; ``payload`` is
    bounded owner-native reference/version data. ``detail`` is drawn from the
    coordinator's safe vocabulary — never a raw exception string.
    """

    provider_id: str
    status: ProvenanceStatus
    leaves: tuple[ProvenanceLeaf, ...] = ()
    payload: Mapping[str, object] = field(default_factory=dict)
    detail: str = ""


@runtime_checkable
class ProvenanceProvider(Protocol):
    """A trusted, code-owned provenance source."""

    provider_id: str

    def collect(self, context: ProvenanceContext) -> ProvenanceResult:
        """Read this provider's declared source under ``context``'s limits."""
        ...
