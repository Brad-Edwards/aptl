"""Immediate native-evidence request model and acquisition entry point."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from aptl.core.correlation.clock import ClockProvider, SystemClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult, acquire_evidence
from aptl.core.evidence.protocol import RunScope
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


def acquire_native_evidence(request: NativeEvidenceRequest) -> AcquisitionResult:
    """Collect every immediate native binding or return a failed disposition."""

    from aptl.backends.raes_evidence_acquisition import (
        _OnDemandNativeCollector,
        _native_bindings,
        _persist_capture_plan,
    )

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
