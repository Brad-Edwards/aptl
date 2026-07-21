"""The evidence-acquisition coordinator (EXP-010 / issue #752 preflight
"Lifecycle and terminal semantics").

``acquire_evidence`` drives a set of admitted :class:`~aptl.core.experiment.
capture_registry.CaptureBinding`s against their trusted collectors around a
trial body:

1. START each admitted collector (after its source is ready) — a startup
   failure aborts before the trial body and still runs cleanup.
2. Run the trial body (participant actions / workflows — supplied by the
   caller; in EXP-010 PR 2 exercised with fakes, wired live by #437/#459).
3. STOP collectors in REVERSE order from a ``finally`` boundary, even when the
   trial body or another collector fails.
4. Bound / redact / hash / persist each captured outcome content-addressably
   and construct ACES evidence records + explicit references.
5. Compute the overall :class:`~aptl.core.evidence.outcomes.
   AcquisitionDisposition`; only ``SEALED_READY`` is ready for the #444 seal.

The coordinator owns deadlines, quotas, clock, path allocation, hashing,
redaction, media checks, persistence, diagnostics, and record construction; a
collector only reports typed bytes/counters/failures. Collector failures are
typed outcome DATA projected into safe ACES diagnostics — no second exception
hierarchy, and no overloading of ``LabResult`` startup readiness.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from aces_contracts.contracts import ExperimentEvidenceRecordModel
from aces_contracts.diagnostics import Diagnostic

from aptl.core.correlation.clock import ClockProvider
from aptl.core.evidence._persist import EvidenceRef, media_type_supported, persist_success_outcome
from aptl.core.evidence.outcomes import (
    STATUS_DIAGNOSTIC_CODES,
    SUCCESS_STATUSES,
    AcquisitionDisposition,
    CollectorStatus,
    capture_diagnostic,
)
from aptl.core.evidence.protocol import Collector, CollectorContext, CollectorOutcome
from aptl.core.experiment.capture_registry import CaptureBinding

#: Statuses that abort the attempt before participant action (source never
#: came up), yielding an INCONCLUSIVE disposition.
_ABORTING_STATUSES: frozenset[CollectorStatus] = frozenset(
    {CollectorStatus.SOURCE_UNAVAILABLE, CollectorStatus.STARTUP_FAILURE}
)

#: Statuses that invalidate a REQUIRED capture unless the policy explicitly
#: accepted the degradation.
_HARD_FAILURE_STATUSES: frozenset[CollectorStatus] = frozenset(
    {
        CollectorStatus.MID_RUN_LOSS,
        CollectorStatus.TRUNCATION,
        CollectorStatus.CLOCK_SKEW,
        CollectorStatus.TIMEOUT,
        CollectorStatus.FINALIZATION_FAILURE,
    }
)

_CODE_NO_COLLECTOR = "aptl.experiment-capture.no-collector-for-binding"
_CODE_REGISTRATION_MISMATCH = "aptl.experiment-capture.collector-registration-mismatch"
_CODE_MEDIA_MISMATCH = "aptl.experiment-capture.media-type-mismatch"


@dataclass(frozen=True)
class CollectorReport:
    """The per-binding acquisition report (a projection safe for diagnostics)."""

    registration_id: str
    requirement_id: str
    status: CollectorStatus
    accepted_degradation: bool
    evidence_record_id: str | None = None
    diagnostic_code: str | None = None


@dataclass(frozen=True)
class AcquisitionResult:
    """The one-shot result of :func:`acquire_evidence` for one trial's capture set."""

    disposition: AcquisitionDisposition
    records: tuple[ExperimentEvidenceRecordModel, ...]
    refs: tuple[EvidenceRef, ...]
    reports: tuple[CollectorReport, ...]
    diagnostics: tuple[Diagnostic, ...]


@dataclass(frozen=True)
class _Started:
    """A collector that started successfully, plus its binding and opaque handle."""

    binding: CaptureBinding
    collector: Collector
    handle: object


def _binding_key(binding: CaptureBinding) -> tuple[str, str]:
    """Return a binding's capture-spec-scoped identity.

    Keying per-binding acquisition state by the bare ``requirement_id`` would
    let two bindings from DIFFERENT capture specs that reuse a requirement id
    overwrite each other's outcome; the ``(capture_spec_id, requirement_id)``
    pair is unique within one admitted plan.
    """
    return (binding.capture_spec_id, binding.requirement_id)


def _context(
    binding: CaptureBinding, *, run_id: str, planned_trial_id: str, attempt_id: str, clock: ClockProvider
) -> CollectorContext:
    """Build the narrow immutable context handed to a collector at start."""
    return CollectorContext(
        planned_trial_id=planned_trial_id,
        run_id=run_id,
        attempt_id=attempt_id,
        binding=binding,
        deadline_seconds=float(binding.limits.max_duration_s),
        clock=clock,
    )


def _failed_outcome(status: CollectorStatus, clock: ClockProvider, detail: str) -> CollectorOutcome:
    """Build a typed failure outcome stamped with the coordinator's observation clock."""
    now = clock.now()
    return CollectorOutcome(status=status, started_at=now, finished_at=now, detail=detail)


def _start_all(
    plan: Sequence[tuple[CaptureBinding, Collector]],
    *,
    run_id: str,
    planned_trial_id: str,
    attempt_id: str,
    clock: ClockProvider,
) -> tuple[list[_Started], dict[tuple[str, str], CollectorOutcome]]:
    """Start collectors in order; on the first startup failure, stop early.

    Returns the successfully-started collectors and a map of binding key ->
    startup-failure outcome for the collectors that never started (the failing
    one plus every one after it).
    """
    started: list[_Started] = []
    not_started: dict[tuple[str, str], CollectorOutcome] = {}
    aborted = False
    for binding, collector in plan:
        if aborted:
            not_started[_binding_key(binding)] = _failed_outcome(
                CollectorStatus.STARTUP_FAILURE, clock, "not started (an earlier collector failed to start)"
            )
            continue
        context = _context(
            binding, run_id=run_id, planned_trial_id=planned_trial_id, attempt_id=attempt_id, clock=clock
        )
        try:
            handle = collector.start(context)
        except Exception:  # noqa: BLE001 - normalized to a typed outcome, never re-raised
            not_started[_binding_key(binding)] = _failed_outcome(
                CollectorStatus.STARTUP_FAILURE, clock, "collector raised during start"
            )
            aborted = True
            continue
        started.append(_Started(binding=binding, collector=collector, handle=handle))
    return started, not_started


def _stop_all(started: Sequence[_Started], clock: ClockProvider) -> dict[tuple[str, str], CollectorOutcome]:
    """Stop started collectors in REVERSE order; a stop raising becomes a finalization failure."""
    outcomes: dict[tuple[str, str], CollectorOutcome] = {}
    for entry in reversed(started):
        try:
            outcome = entry.collector.stop(entry.handle)
        except Exception:  # noqa: BLE001 - normalized to a typed outcome, never re-raised
            outcome = _failed_outcome(
                CollectorStatus.FINALIZATION_FAILURE, clock, "collector raised during stop"
            )
        outcomes[_binding_key(entry.binding)] = outcome
    return outcomes


def _resolve_plan(
    bindings: Sequence[CaptureBinding], collectors: Mapping[str, Collector]
) -> tuple[list[tuple[CaptureBinding, Collector]], list[Diagnostic], dict[tuple[str, str], CollectorOutcome]]:
    """Pair each binding with its collector, verifying the pinned registration id.

    A missing or mismatched collector is a coordinator wiring fault, not an
    experiment-input failure: it yields a diagnostic + a SOURCE_UNAVAILABLE
    outcome for that binding (INCONCLUSIVE), never a silent skip.
    """
    plan: list[tuple[CaptureBinding, Collector]] = []
    diagnostics: list[Diagnostic] = []
    unavailable: dict[tuple[str, str], CollectorOutcome] = {}
    for binding in bindings:
        collector = collectors.get(binding.registration_id)
        address = f"capture.{binding.capture_spec_id}.{binding.requirement_id}"
        if collector is None:
            diagnostics.append(capture_diagnostic(_CODE_NO_COLLECTOR, address, "no collector wired for the pinned registration"))
            unavailable[_binding_key(binding)] = CollectorOutcome(
                status=CollectorStatus.SOURCE_UNAVAILABLE, started_at="", finished_at="", detail="no collector"
            )
            continue
        if collector.registration_id != binding.registration_id:
            diagnostics.append(
                capture_diagnostic(_CODE_REGISTRATION_MISMATCH, address, "collector registration id does not match the pinned binding")
            )
            unavailable[_binding_key(binding)] = CollectorOutcome(
                status=CollectorStatus.SOURCE_UNAVAILABLE, started_at="", finished_at="", detail="registration mismatch"
            )
            continue
        plan.append((binding, collector))
    return plan, diagnostics, unavailable


def _process_outcome(
    binding: CaptureBinding,
    outcome: CollectorOutcome,
    *,
    run_store: object,
    run_id: str,
    planned_trial_id: str,
) -> tuple[CollectorReport, ExperimentEvidenceRecordModel | None, EvidenceRef | None, Diagnostic | None]:
    """Turn one collector outcome into a report (+ record/ref for a success, + diagnostic for a failure)."""
    accepted = binding.accepted_limitation is not None
    if outcome.status not in SUCCESS_STATUSES:
        code = STATUS_DIAGNOSTIC_CODES.get(outcome.status, "aptl.experiment-capture.unknown-failure")
        address = f"capture.{binding.capture_spec_id}.{binding.requirement_id}"
        diagnostic = capture_diagnostic(code, address, f"collector reported {outcome.status.value}")
        report = CollectorReport(
            registration_id=binding.registration_id,
            requirement_id=binding.requirement_id,
            status=outcome.status,
            accepted_degradation=accepted,
            diagnostic_code=code,
        )
        return report, None, None, diagnostic

    if not media_type_supported(outcome, binding):
        address = f"capture.{binding.capture_spec_id}.{binding.requirement_id}"
        diagnostic = capture_diagnostic(_CODE_MEDIA_MISMATCH, address, "captured media type is not one the requirement expects")
        report = CollectorReport(
            registration_id=binding.registration_id,
            requirement_id=binding.requirement_id,
            status=CollectorStatus.MID_RUN_LOSS,
            accepted_degradation=accepted,
            diagnostic_code=_CODE_MEDIA_MISMATCH,
        )
        return report, None, None, diagnostic

    processed = persist_success_outcome(
        binding=binding,
        outcome=outcome,
        run_store=run_store,  # type: ignore[arg-type]
        run_id=run_id,
        planned_trial_id=planned_trial_id,
        captured_at=outcome.finished_at,
    )
    report = CollectorReport(
        registration_id=binding.registration_id,
        requirement_id=binding.requirement_id,
        status=processed.effective_status,
        accepted_degradation=accepted,
        evidence_record_id=processed.record.evidence_record_id,
        diagnostic_code=(
            STATUS_DIAGNOSTIC_CODES.get(processed.effective_status)
            if processed.effective_status not in SUCCESS_STATUSES
            else None
        ),
    )
    return report, processed.record, processed.ref, None


def _disposition(reports: Sequence[CollectorReport]) -> AcquisitionDisposition:
    """Compute the overall disposition from the per-binding effective statuses."""
    if any(r.status in _ABORTING_STATUSES for r in reports):
        return AcquisitionDisposition.INCONCLUSIVE
    partial = False
    for report in reports:
        if report.status in _HARD_FAILURE_STATUSES:
            if not report.accepted_degradation:
                return AcquisitionDisposition.INVALIDATED
            partial = True
    return AcquisitionDisposition.COMPLETED_PARTIAL if partial else AcquisitionDisposition.SEALED_READY


def acquire_evidence(
    *,
    bindings: Sequence[CaptureBinding],
    collectors: Mapping[str, Collector],
    run_store: object,
    run_id: str,
    planned_trial_id: str,
    attempt_id: str,
    clock: ClockProvider,
    trial_body: Callable[[], None] = lambda: None,
) -> AcquisitionResult:
    """Acquire evidence for one trial's admitted capture bindings.

    ``trial_body`` is the work that runs while collectors are live (participant
    actions / orchestrator workflows). It runs BETWEEN start and the reverse-
    order stop; if it raises, collectors are still stopped (the raise is
    swallowed here — the trial's own failure is the caller's concern, cleanup
    is ours). Returns a one-shot :class:`AcquisitionResult`; nothing partial in
    between.
    """
    plan, diagnostics, unavailable = _resolve_plan(bindings, collectors)
    started, not_started = _start_all(
        plan, run_id=run_id, planned_trial_id=planned_trial_id, attempt_id=attempt_id, clock=clock
    )

    if started:
        try:
            trial_body()
        except Exception:  # noqa: BLE001 - the trial's failure is not the coordinator's to raise; cleanup still runs
            pass
    stop_outcomes = _stop_all(started, clock)

    outcomes_by_key: dict[tuple[str, str], CollectorOutcome] = {**unavailable, **not_started, **stop_outcomes}
    reports: list[CollectorReport] = []
    records: list[ExperimentEvidenceRecordModel] = []
    refs: list[EvidenceRef] = []
    all_diagnostics: list[Diagnostic] = list(diagnostics)
    for binding in bindings:
        outcome = outcomes_by_key[_binding_key(binding)]
        report, record, ref, diagnostic = _process_outcome(
            binding, outcome, run_store=run_store, run_id=run_id, planned_trial_id=planned_trial_id
        )
        reports.append(report)
        if record is not None and ref is not None:
            records.append(record)
            refs.append(ref)
        if diagnostic is not None:
            all_diagnostics.append(diagnostic)

    return AcquisitionResult(
        disposition=_disposition(reports),
        records=tuple(records),
        refs=tuple(refs),
        reports=tuple(reports),
        diagnostics=tuple(all_diagnostics),
    )
