"""Trusted adapter wiring for the built-in collector fleet (EXP-010 / #752).

This is the trusted composition code that maps a non-executable
``registration_id`` to a live :class:`~aptl.core.evidence.protocol.Collector`
— the ONE place where declared capability becomes a running collector.
Experiment input never reaches here: the caller (execution / #437 / #459, or a
test) constructs the narrow :class:`~aptl.core.evidence.adapters.sources.
WindowedSource`s from the real source owners and hands them in keyed by
registration id. Only ids in the built-in fleet are accepted — an unknown id
fails closed rather than resolving to anything.
"""

from __future__ import annotations

from collections.abc import Mapping

from aptl.core.evidence.adapters.sources import WindowedQueryCollector, WindowedSource
from aptl.core.evidence.protocol import Collector
from aptl.core.experiment.capture_registrations import BUILTIN_REGISTRATIONS

#: The registration ids the built-in wiring will bind a collector for.
BUILTIN_REGISTRATION_IDS: frozenset[str] = frozenset(
    registration.registration_id for registration in BUILTIN_REGISTRATIONS
)


def build_collectors(sources: Mapping[str, WindowedSource]) -> dict[str, Collector]:
    """Wire each provided windowed source to its generic collector, keyed by registration id.

    Raises :class:`ValueError` for a registration id outside the built-in
    fleet — the coordinator then has no collector for an unrecognized binding
    and reports it as unavailable, never silently resolving it.
    """
    collectors: dict[str, Collector] = {}
    for registration_id, source in sources.items():
        if registration_id not in BUILTIN_REGISTRATION_IDS:
            raise ValueError(f"unknown collector registration id: {registration_id!r}")
        collectors[registration_id] = WindowedQueryCollector(registration_id, source)
    return collectors
