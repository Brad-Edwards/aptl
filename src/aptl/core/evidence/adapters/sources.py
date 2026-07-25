"""Windowed-query collector framework for trusted built-in sources (EXP-010 /
issue #752 preflight "Narrow collector boundary").

Most APTL evidence sources are windowed queries: given the trial's start/stop
observation window, return the events in it. :class:`WindowedQueryCollector`
is the one generic :class:`~aptl.core.evidence.protocol.Collector` for all of
them — it stamps the window from the injected clock, calls a narrow
:class:`WindowedSource`, and maps the source's typed
:class:`SourceResult` onto a :class:`~aptl.core.evidence.protocol.
CollectorOutcome`. A source reports OK / legitimately-empty / a distinct
failure — the empty-on-error collapse of ``collectors.py`` is never allowed to
read as success.

A :class:`WindowedSource` is the ONLY thing a collector talks to; it wraps a
source owner (``DeploymentBackend``, a SOC ``curl_safe`` client, the run
archive) at the level where the failure signal exists, and is injected by
trusted composition code — never selected by experiment input.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from aptl.core.evidence.outcomes import SUCCESS_STATUSES, CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, CollectorOutcome


@dataclass(frozen=True)
class SourceResult:
    """One windowed source's typed result.

    ``status`` distinguishes a real capture / legitimate emptiness from each
    failure the source can detect (a returncode, a ``None`` HTTP result, a
    missing archive file). ``records`` are structured events the coordinator
    will serialize + redact; an over-limit source reports :attr:`dropped_count`
    rather than silently losing events.
    """

    status: CollectorStatus
    records: list[dict[str, object]] = field(default_factory=list)
    dropped_count: int = 0
    source_min_time: str | None = None
    source_max_time: str | None = None


@runtime_checkable
class WindowedSource(Protocol):
    """A narrow, source-owned windowed query returning a typed result."""

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        """Return the source's events in ``[start_iso, end_iso]`` as a typed result."""
        ...


@dataclass(frozen=True)
class _WindowHandle:
    """Opaque per-start handle: the window's start time + the observation clock."""

    started_at: str
    clock: object


class CallableWindowedSource:
    """Adapt a plain ``fetch(start, end) -> SourceResult`` callable to a source.

    Lets a concrete built-in source be a thin function (or a bound method of a
    source owner) rather than a class, while keeping the narrow protocol.
    """

    def __init__(self, fetch: Callable[[str, str], SourceResult]) -> None:
        """Wrap a ``fetch(start_iso, end_iso) -> SourceResult`` callable."""
        self._fetch = fetch

    def fetch(self, start_iso: str, end_iso: str) -> SourceResult:
        """Delegate to the wrapped callable."""
        return self._fetch(start_iso, end_iso)


class WindowedQueryCollector:
    """The generic collector for a windowed source (media type ``application/json``).

    ``registration_id`` must match the pinned binding's; the coordinator
    verifies it. ``start`` records the window open from the injected clock and
    ``stop`` closes it, queries the source, and maps the typed result — a
    source failure becomes a distinct :class:`CollectorStatus`, never an empty
    success.
    """

    def __init__(self, registration_id: str, source: WindowedSource) -> None:
        """Bind this collector to its registration id and windowed source."""
        self._registration_id = registration_id
        self._source = source

    @property
    def registration_id(self) -> str:
        """The registration this collector realizes."""
        return self._registration_id

    @staticmethod
    def start(context: CollectorContext) -> _WindowHandle:
        """Open the observation window from the injected clock."""
        return _WindowHandle(started_at=context.clock.now(), clock=context.clock)

    def stop(self, handle: _WindowHandle) -> CollectorOutcome:
        """Close the window, query the source, and map its typed result."""
        finished_at = handle.clock.now()
        result = self._source.fetch(handle.started_at, finished_at)
        return _to_outcome(result, handle.started_at, finished_at)


def _to_outcome(result: SourceResult, started_at: str, finished_at: str) -> CollectorOutcome:
    """Map a :class:`SourceResult` to a :class:`CollectorOutcome`.

    A source failure passes through without chunks; a success serializes the
    structured records to ``application/json`` (empty records are a legitimate
    ``EMPTY_OK``, never a failure).
    """
    if result.status not in SUCCESS_STATUSES:
        return CollectorOutcome(
            status=result.status,
            started_at=started_at,
            finished_at=finished_at,
            dropped_count=result.dropped_count,
            detail=f"source reported {result.status.value}",
        )
    status = CollectorStatus.OK if result.records else CollectorStatus.EMPTY_OK
    chunks = [json.dumps(result.records, separators=(",", ":")).encode("utf-8")]
    return CollectorOutcome(
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        chunks=chunks,
        media_type="application/json",
        event_count=len(result.records),
        dropped_count=result.dropped_count,
        source_min_time=result.source_min_time,
        source_max_time=result.source_max_time,
    )
