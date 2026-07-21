"""The narrow collector boundary for evidence acquisition (EXP-010 / issue
#752 preflight "Narrow collector boundary").

A collector receives ONLY an immutable :class:`CollectorContext` — the
planned-trial / run / attempt IDs, its pinned :class:`~aptl.core.experiment.
capture_registry.CaptureBinding` and window, a deadline and limits, and a
:class:`~aptl.core.correlation.clock.ClockProvider`. It NEVER receives the
``ExperimentController``, the ACES runtime target, ``LocalRunStore``, raw
filesystem paths, ``EnvVars``, the full application config, or a generic
command/HTTP client. It reports source bytes/chunks and typed counters or a
typed :class:`~aptl.core.evidence.outcomes.CollectorStatus` failure through
:class:`CollectorOutcome`; it cannot choose an archive path, hash, redact, or
construct a portable ACES evidence record — the coordinator owns all of that.

The source-specific work (a `DeploymentBackend.container_logs_capture`, a SOC
`curl_safe` call, an MCP result envelope, the Kali sidecar) is wrapped by a
trusted adapter that is injected into the collector by composition code — it
is never selected by experiment input.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from aptl.core.correlation.clock import ClockProvider
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.experiment.capture_registry import CaptureBinding

#: A collector's opaque per-start handle (e.g. a session id or a buffer
#: reference). The coordinator treats it as opaque and only hands it back to
#: the same collector's :meth:`Collector.stop`.
CollectorHandle = object


@dataclass(frozen=True)
class CollectorContext:
    """The immutable admitted context a collector is given at start.

    Deliberately narrow (preflight): identity + the pinned binding + a
    deadline + a clock. No store, no paths, no config, no backend handle.
    """

    planned_trial_id: str
    run_id: str
    attempt_id: str
    binding: CaptureBinding
    deadline_seconds: float
    clock: ClockProvider


@dataclass(frozen=True)
class CollectorOutcome:
    """The typed result a collector reports from :meth:`Collector.stop`.

    ``chunks`` are the raw source bytes the coordinator will hash, redact
    (structured payloads only), quota, and content-address — the collector
    never persists them itself. ``status`` distinguishes success / legitimate
    emptiness from each failure mode (never empty-on-error == success).
    ``source_min_time`` / ``source_max_time`` are the source's own event
    timestamps (RFC-3339), kept distinct from the collector's
    ``started_at`` / ``finished_at`` observation clock so proximity is never
    mistaken for causality.
    """

    status: CollectorStatus
    started_at: str
    finished_at: str
    chunks: Sequence[bytes] = ()
    media_type: str | None = None
    event_count: int = 0
    dropped_count: int = 0
    source_min_time: str | None = None
    source_max_time: str | None = None
    observer_effect: str | None = None
    detail: str | None = None
    source_pipeline: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class Collector(Protocol):
    """A trusted, code-owned collector realizing one registration.

    ``registration_id`` MUST equal the ``registration_id`` of the pinned
    binding the coordinator drives it for — the coordinator verifies this
    (never re-matching a changed registry). ``start`` opens the source and
    returns an opaque handle; ``stop`` closes it and returns the typed
    outcome. Neither call may raise for an ordinary source failure — the
    failure is reported as a :class:`CollectorStatus`; only genuinely
    unexpected internal errors propagate (and the coordinator normalizes
    them into a safe diagnostic).
    """

    @property
    def registration_id(self) -> str:
        """The registration this collector realizes (verified against the binding)."""
        ...

    def start(self, context: CollectorContext) -> CollectorHandle:
        """Open the source and return an opaque handle for :meth:`stop`."""
        ...

    def stop(self, handle: CollectorHandle) -> CollectorOutcome:
        """Close the source and return the typed capture outcome."""
        ...
