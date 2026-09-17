"""Immediate native-evidence request model and acquisition entry point."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.core.correlation.clock import ClockProvider, SystemClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult, acquire_evidence
from aptl.core.evidence.protocol import RunScope
from aptl.core.runstore import LocalRunStore

if TYPE_CHECKING:
    from aptl.backends.raes_realization_model import AptlRealization
    from aptl.core.experiment.capture_plan import CapturePlan


@dataclass(frozen=True)
class NativeEvidenceRequest:
    """All authority and runtime inputs for immediate native acquisition."""

    plan: CapturePlan
    backend: object
    realization: AptlRealization
    project_dir: Path
    indexer_auth: tuple[str, str]
    thehive_api_key: str
    run_store: LocalRunStore
    run_id: str
    clock: ClockProvider | None = None


def acquire_native_evidence(request: NativeEvidenceRequest) -> AcquisitionResult:
    """Collect every immediate native binding or return a failed disposition."""

    from aptl.backends.raes_evidence_acquisition import (
        _OnDemandNativeCollector,
        _native_bindings,
        _persist_capture_plan,
        TechVaultNativeEvidenceOwner,
    )

    if not isinstance(request.run_store, LocalRunStore):
        raise TypeError("native evidence requires a local run store")
    bindings = _native_bindings(request.plan)
    _persist_capture_plan(request.plan, request.run_store, request.run_id)
    owner = TechVaultNativeEvidenceOwner(
        backend=request.backend,
        realization=request.realization,
        project_dir=request.project_dir,
        indexer_auth=request.indexer_auth,
        thehive_api_key=request.thehive_api_key,
    )
    sources = owner.sources()
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
