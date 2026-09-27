"""Immediate native-evidence request model and acquisition entry point."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.correlation.clock import ClockProvider, SystemClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult, acquire_evidence
from aptl.core.evidence.adapters.sources import (
    SourceResult,
    WindowedSource,
    _to_outcome,
)
from aptl.core.evidence.content_store import create_run_json_once
from aptl.core.evidence.outcomes import CollectorStatus
from aptl.core.evidence.protocol import CollectorContext, CollectorOutcome, RunScope
from aptl.core.experiment.capture_registry import CaptureBinding
from aptl.core.runstore import LocalRunStore

if TYPE_CHECKING:
    from aptl.backends.scenario_capture import ResolvedScenarioCapture
    from aptl.backends.raes_realization_model import AptlRealization
    from aptl.core.experiment.capture_plan import CapturePlan


@dataclass(frozen=True)
class NativeEvidenceRequest:
    """All authority and runtime inputs for immediate native acquisition."""

    plan: CapturePlan
    backend: object
    realization: AptlRealization
    project_dir: Path
    environment: Mapping[str, str]
    run_store: LocalRunStore
    run_id: str
    capture_selection: ResolvedScenarioCapture
    clock: ClockProvider | None = None


@dataclass(frozen=True)
class _OnDemandHandle:
    """Collector context and the exact native-check start instant."""

    context: CollectorContext
    started_at: str


def _parse_timestamp(value: str) -> datetime:
    """Parse the canonical UTC timestamp form emitted by capture clocks."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _deadline(started_at: str, seconds: float) -> str:
    """Return the admitted deadline measured from a collector start."""

    value = _parse_timestamp(started_at) + timedelta(seconds=seconds)
    return value.isoformat().replace("+00:00", "Z")


def _source_times_inside_actual_window(
    result: SourceResult, started_at: str, finished_at: str
) -> bool:
    """Return whether all reported source instants fit the actual window."""

    try:
        start = _parse_timestamp(started_at)
        finish = _parse_timestamp(finished_at)
        source_min = (
            _parse_timestamp(result.source_min_time)
            if result.source_min_time is not None
            else None
        )
        source_max = (
            _parse_timestamp(result.source_max_time)
            if result.source_max_time is not None
            else None
        )
    except (TypeError, ValueError):
        return False
    return (
        start <= finish
        and (source_min is None or start <= source_min <= finish)
        and (source_max is None or start <= source_max <= finish)
        and (source_min is None or source_max is None or source_min <= source_max)
    )


class _OnDemandNativeCollector:
    """Run one bounded native check and close its window after the check."""

    def __init__(self, registration_id: str, source: WindowedSource) -> None:
        self._registration_id = registration_id
        self._source = source

    @property
    def registration_id(self) -> str:
        return self._registration_id

    @staticmethod
    def start(context: CollectorContext) -> _OnDemandHandle:
        return _OnDemandHandle(context=context, started_at=context.clock.now())

    def stop(self, handle: _OnDemandHandle) -> CollectorOutcome:
        result = self._source.fetch(
            handle.started_at,
            _deadline(handle.started_at, handle.context.deadline_seconds),
        )
        finished_at = handle.context.clock.now()
        if not _source_times_inside_actual_window(
            result, handle.started_at, finished_at
        ):
            result = SourceResult(status=CollectorStatus.CLOCK_SKEW)
        return _to_outcome(result, handle.started_at, finished_at)


def _native_bindings(
    plan: CapturePlan,
    selection: ResolvedScenarioCapture,
) -> tuple[CaptureBinding, ...]:
    """Select immediate bindings declared by the admitted adapter."""

    return tuple(
        binding
        for binding in plan.runtime_bindings()
        if binding.registration_id in selection.contribution.native_registration_ids
    )


def _persist_capture_plan(
    plan: CapturePlan, run_store: LocalRunStore, run_id: str
) -> None:
    """Create the run and seal the admitted capture plan exactly once."""

    run_store.create_run(run_id)
    create_run_json_once(
        run_store,
        run_id,
        f"evidence/capture-plans/{plan.plan_id}.json",
        json.loads(plan.canonical_bytes),
    )


def acquire_native_evidence(request: NativeEvidenceRequest) -> AcquisitionResult:
    """Collect every immediate native binding or return a failed disposition."""

    if not isinstance(request.run_store, LocalRunStore):
        raise TypeError("native evidence requires a local run store")
    bindings = _native_bindings(request.plan, request.capture_selection)
    _persist_capture_plan(request.plan, request.run_store, request.run_id)
    runtime_adapter = request.capture_selection.contribution.runtime_adapter
    source_factory = getattr(runtime_adapter, "native_sources", None)
    sources = source_factory(request) if callable(source_factory) else {}
    collectors = {
        binding.registration_id: _OnDemandNativeCollector(
            binding.registration_id,
            sources[binding.registration_id],  # type: ignore[arg-type]
        )
        for binding in bindings
        if binding.registration_id in sources
    }
    return acquire_evidence(
        bindings=bindings,
        collectors=collectors,
        run_store=request.run_store,
        scope=RunScope(
            run_id=request.run_id,
            planned_trial_id=request.plan.plan_id,
            attempt_id="provisioning",
        ),
        clock=request.clock or SystemClockProvider(),
    )


__all__ = ("NativeEvidenceRequest", "acquire_native_evidence")
