"""Clock-provider seam (OBS-002 Stage 1, issue #447).

Implements the preflight's "Clock collection needs one source-owned
provider seam" seam:
``(source_kind, source_id, timestamp_domain, clock_source,
synchronization_status, measured_offset, uncertainty, measurement_time,
observer_effect_ref)``. Collectors and MCP sinks can implement this
seam differently, but must not scatter ``datetime.now(UTC)``,
``Date.now()``, UUIDs, or wall-clock parsing through business logic as an
identity or causality source (preflight "Gotchas").

:func:`utc_now` is the single canonical UTC RFC3339 formatter — a future
stage rewires the three duplicated backend call sites that currently
format ``datetime.now(UTC)`` locally to import this instead, so the
formatting logic has exactly one owner.

Identity is deliberately out of scope here: this module only ever
reports *when* and *how confidently* a source's clock was read. Stable
correlation identity comes from ``aptl.core.correlation.identity``, never
from a clock reading.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from aptl.core.correlation.models import ClockContext

__all__ = [
    "ClockContext",
    "ClockProvider",
    "FixedClockProvider",
    "SystemClockProvider",
    "utc_now",
]


def utc_now() -> str:
    """Return the current UTC time as an RFC3339 string (``...Z`` suffix).

    The single canonical UTC formatter for the whole codebase — callers
    must import this rather than formatting ``datetime.now(UTC)``
    locally, so there is exactly one place that owns the format.
    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class ClockProvider(Protocol):
    """Source-owned clock seam. A future collector implements this
    differently per source (e.g. reading an NTP-disciplined offset)
    without any caller needing to learn a new identity concept."""

    def clock_context(
        self,
        *,
        source_kind: str,
        source_id: str,
        observer_effect_ref: str | None = None,
    ) -> ClockContext: ...

    def now(self) -> str: ...


class SystemClockProvider(ClockProvider):
    """Default provider backed by the host system clock.

    Honest about what a bare system clock can claim: no measured offset
    or uncertainty band (the host has not been NTP-audited by this
    provider), and ``synchronization_status="unknown"`` rather than a
    fabricated "synchronized" claim.
    """

    def now(self) -> str:
        return utc_now()

    def clock_context(
        self,
        *,
        source_kind: str,
        source_id: str,
        observer_effect_ref: str | None = None,
    ) -> ClockContext:
        return ClockContext(
            source_kind=source_kind,
            source_id=source_id,
            timestamp_domain="host-utc",
            clock_source="system",
            synchronization_status="unknown",
            measured_offset=None,
            uncertainty=None,
            measurement_time=self.now(),
            observer_effect_ref=observer_effect_ref,
        )


@dataclass(frozen=True)
class FixedClockProvider(ClockProvider):
    """Test-friendly injectable provider: every field is fixed at
    construction, so both :meth:`now` and :meth:`clock_context` are
    fully deterministic across calls."""

    measurement_time: str
    clock_source: str = "fixed"
    timestamp_domain: str = "host-utc"
    synchronization_status: str = "unknown"
    measured_offset: str | None = None
    uncertainty: str | None = None

    def now(self) -> str:
        return self.measurement_time

    def clock_context(
        self,
        *,
        source_kind: str,
        source_id: str,
        observer_effect_ref: str | None = None,
    ) -> ClockContext:
        return ClockContext(
            source_kind=source_kind,
            source_id=source_id,
            timestamp_domain=self.timestamp_domain,
            clock_source=self.clock_source,
            synchronization_status=self.synchronization_status,
            measured_offset=self.measured_offset,
            uncertainty=self.uncertainty,
            measurement_time=self.measurement_time,
            observer_effect_ref=observer_effect_ref,
        )
