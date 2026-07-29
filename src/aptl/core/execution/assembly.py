"""Terminal-attempt context assembly for the execution controller (#437/#459 →
EXP-009 / ADR-050).

This module holds the value types the execution controller drives on and the
pure builders that turn one executed (or interrupted) trial into the immutable
:class:`~aptl.core.archival.context.TerminalAttemptContext` the archive
coordinator seals. The builders take the run store, clock, and a single bundled
:class:`AssemblyInputs` explicitly, so the controller stays a thin orchestration
seam and the composition logic is independently testable.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum

import rfc8785
from raes_contracts.contracts import (
    ExperimentApparatusContextModel,
    ExperimentArtifactRefModel,
    ExperimentCaptureSpecReferenceModel,
    ExperimentChecksumModel,
    ExperimentEvidenceRecordModel,
    ExperimentEvidenceRecordReferenceModel,
    ExperimentReferenceModel,
    ExperimentResultSummaryModel,
    ExperimentRunTraceabilityModel,
    ExperimentScenarioSnapshotReferenceModel,
    ExperimentTaskModel,
    ParticipantImplementationProvenanceModel,
)
from raes_contracts.contracts.experiment_capture import ExperimentRawEvidenceContentModel
from raes_contracts.contracts.experiment_manifest_references import (
    ExperimentEvidenceSatisfactionReferenceModel,
    ExperimentRunEvidenceArtifactReferenceModel,
)

from aptl.core.archival.context import TerminalAttemptContext
from aptl.core.archival.seal import SealedArtifactSpec
from aptl.core.archival.status import TerminalCause
from aptl.core.correlation.clock import ClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult
from aptl.core.evidence.protocol import RunScope
from aptl.core.execution.bridges import (
    clock_context_from_provider,
    evidence_artifacts_from_acquisition,
    parameter_set_from_trial,
    sealed_artifacts_from_acquisition,
    stochastic_controls_from_trial,
    validate_result_summaries,
)
from aptl.core.experiment.trial_plan_models import PlannedTrial, TrialPlan
from aptl.core.runstore import LocalRunStore

_JSON_MEDIA_TYPE = "application/json"

_LIFECYCLE_ARTIFACT_ID = "lifecycle-attempt-record"
_LIFECYCLE_CAPTURE_SPEC = "aptl.lifecycle"
_LIFECYCLE_SUBDIR = "lifecycle"
_LIFECYCLE_MAX_BYTES = 64 * 1024
#: Run-relative subdirectory of the create-once evidence-record ledger (matches
#: the evidence coordinator's ``_LEDGER_SUBDIR``).
_EVIDENCE_LEDGER_SUBDIR = "evidence/records"

#: The evidence-satisfaction reference the always-present lifecycle attestation
#: carries. An authored task whose observation/metric-evidence requirements name
#: this ref is satisfied by the lifecycle attestation alone; a richer task is
#: satisfied by the real captured evidence artifacts.
LIFECYCLE_OBSERVATION_REF = "aptl.lifecycle.observation"


class TrialTerminalSignal(str, Enum):
    """How the injected workload reports one executed trial ended."""

    COMPLETED = "completed"
    SCENARIO_FAILURE = "scenario-failure"
    EVALUATOR_FAILURE = "evaluator-failure"
    CANCELLED = "cancelled"
    POLICY_STOP = "policy-stop"
    INTERRUPTED = "interrupted"


#: Fixed workload-signal -> terminal-cause mapping (evidence invalidation is
#: handled separately, since it dominates the workload signal).
_SIGNAL_CAUSE_MAP: dict[TrialTerminalSignal, TerminalCause] = {
    TrialTerminalSignal.SCENARIO_FAILURE: TerminalCause.SCENARIO_FAILURE,
    TrialTerminalSignal.EVALUATOR_FAILURE: TerminalCause.EVALUATOR_FAILURE,
    TrialTerminalSignal.CANCELLED: TerminalCause.CANCELLATION,
    TrialTerminalSignal.POLICY_STOP: TerminalCause.POLICY_STOP,
    TrialTerminalSignal.INTERRUPTED: TerminalCause.INFRASTRUCTURE_INTERRUPTION,
}


@dataclass(frozen=True)
class TrialOutcome:
    """What the injected workload returns for one executed trial."""

    signal: TrialTerminalSignal
    result_summaries: Mapping[str, ExperimentResultSummaryModel] = field(default_factory=dict)
    evaluator_outcome: str | None = None
    deviations: tuple[str, ...] = ()
    invalidation_reason: str | None = None


@dataclass(frozen=True)
class TrialExecutionContext:
    """The identity handed to the workload for one trial."""

    attempt_id: str
    planned_trial: PlannedTrial
    scope: RunScope


@dataclass(frozen=True)
class AdmittedExperiment:
    """The admitted, owner-native experiment identities the executor seals against.

    Assembled by the caller from admission output: the immutable plan, the
    re-resolved task, the sealed scenario snapshot reference, the apparatus
    projection, and participant provenance. The executor consumes these; it never
    re-admits or re-resolves them itself.
    """

    plan: TrialPlan
    task: ExperimentTaskModel
    scenario_snapshot_ref: ExperimentScenarioSnapshotReferenceModel
    apparatus_context: ExperimentApparatusContextModel
    participant_provenance: ParticipantImplementationProvenanceModel | None = None
    run_version: str = "1.0.0"


Workload = Callable[[TrialExecutionContext], TrialOutcome]


@dataclass(frozen=True)
class TerminalCauseResolution:
    """A resolved terminal cause plus the fields it implies."""

    # TerminalCause, kept as ``object`` so downstream annotations stay light.
    cause: object
    evaluator_outcome: str | None = None
    invalidation_reason: str | None = None


@dataclass(frozen=True)
class _LifecycleEvidence:
    """The lifecycle attestation's artifact ref, evidence record, and seal specs."""

    artifact: ExperimentArtifactRefModel
    record: ExperimentEvidenceRecordModel
    sealed_spec: SealedArtifactSpec
    record_spec: SealedArtifactSpec


@dataclass(frozen=True)
class AssemblyInputs:
    """Bundled inputs for :func:`assemble_context` (one executed/interrupted trial)."""

    admitted: AdmittedExperiment
    planned_trial: PlannedTrial
    attempt_id: str
    scope: RunScope
    acquisition: AcquisitionResult
    outcome: TrialOutcome | None
    resolution: TerminalCauseResolution
    started_at: str
    ended_at: str


def write_lifecycle_evidence(
    store: LocalRunStore,
    *,
    attempt_id: str,
    scope: RunScope,
    resolution: TerminalCauseResolution,
    ended_at: str,
) -> _LifecycleEvidence:
    """Write the attempt's terminal attestation as content-addressed evidence.

    Always present, so an attempt that captured nothing still has the
    evidence artifact, evidence record, capture-spec ref, and result-summary
    anchor the RAES run record requires.
    """
    from aptl.core.evidence.content_store import create_content_addressed

    payload = {
        "schema_version": "aptl.lifecycle-attestation/v1",
        "attempt_id": attempt_id,
        "planned_trial_id": scope.planned_trial_id,
        "terminal_cause": str(resolution.cause),
        "recorded_at": ended_at,
    }
    blob = rfc8785.dumps(payload)
    insertion = create_content_addressed(
        store, attempt_id, [blob], subdir=_LIFECYCLE_SUBDIR, max_bytes=_LIFECYCLE_MAX_BYTES
    )
    digest_hex = hashlib.sha256(blob).hexdigest()
    artifact = ExperimentArtifactRefModel(
        artifact_id=_LIFECYCLE_ARTIFACT_ID,
        role="documentation",
        media_type=_JSON_MEDIA_TYPE,
        uri=insertion.relative_path,
        checksum=ExperimentChecksumModel(algorithm="sha256", value=digest_hex),
        size_bytes=insertion.size,
        created_at=ended_at,
        source="aptl execution controller lifecycle attestation",
        satisfies_refs=[
            ExperimentEvidenceSatisfactionReferenceModel(
                ref_kind="evidence", ref_id=LIFECYCLE_OBSERVATION_REF
            )
        ],
        sensitivity="internal",
    )
    record = ExperimentEvidenceRecordModel(
        schema_version="experiment-evidence-record/v1",
        evidence_record_id=f"lifecycle-{attempt_id}",
        record_version="1.0.0",
        capture_spec_ref=ExperimentCaptureSpecReferenceModel(
            ref_kind="capture-spec", ref_id=_LIFECYCLE_CAPTURE_SPEC, ref_version="1.0.0"
        ),
        capture_requirement_ref="aptl.lifecycle.attempt-record",
        run_ref=ExperimentReferenceModel(ref_kind="run", ref_id=attempt_id),
        source_refs=[ExperimentReferenceModel(ref_kind="backend", ref_id="aptl")],
        evidence_kind="log",
        captured_at=ended_at,
        capture_window_ref="attempt",
        raw_content=ExperimentRawEvidenceContentModel(artifact_ref=artifact),
        sensitivity="internal",
        redaction_state="none",
    )
    sealed_spec = SealedArtifactSpec.from_artifact_ref(
        run_relative_path=insertion.relative_path, artifact_ref=artifact, role="lifecycle"
    )
    # Persist the evidence RECORD too (not only its content blob), so the
    # record the run traceability references is itself in the sealed byte
    # graph — a marker can never claim a record that is absent from disk.
    record_relpath = f"{_EVIDENCE_LEDGER_SUBDIR}/{record.evidence_record_id}.json"
    store.create_run_json_once(
        attempt_id, record_relpath, record.model_dump(mode="json", exclude_none=True)
    )
    record_spec = SealedArtifactSpec(
        path=record_relpath, media_type=_JSON_MEDIA_TYPE, role="evidence-record"
    )
    return _LifecycleEvidence(
        artifact=artifact, record=record, sealed_spec=sealed_spec, record_spec=record_spec
    )


def acquisition_record_specs(
    acquisition: AcquisitionResult,
) -> tuple[SealedArtifactSpec, ...]:
    """Sealed specs for each acquisition evidence record's ledger file.

    The evidence coordinator persists every record create-once at
    ``evidence/records/<id>.json``; sealing them binds the records the run
    traceability references into the inventory.
    """
    return tuple(
        SealedArtifactSpec(
            path=f"{_EVIDENCE_LEDGER_SUBDIR}/{record.evidence_record_id}.json",
            media_type=_JSON_MEDIA_TYPE,
            role="evidence-record",
        )
        for record in acquisition.records
    )


def build_traceability(
    lifecycle: _LifecycleEvidence, acquisition: AcquisitionResult, attempt_id: str
) -> ExperimentRunTraceabilityModel:
    """Compose the run traceability naming the lifecycle + acquisition records."""
    capture_spec_refs = [lifecycle.record.capture_spec_ref]
    evidence_record_refs = [
        ExperimentEvidenceRecordReferenceModel(
            ref_kind="evidence-record",
            ref_id=lifecycle.record.evidence_record_id,
            ref_version=lifecycle.record.record_version,
        )
    ]
    seen_specs = {lifecycle.record.capture_spec_ref.ref_id}
    for record in acquisition.records:
        if record.capture_spec_ref.ref_id not in seen_specs:
            capture_spec_refs.append(record.capture_spec_ref)
            seen_specs.add(record.capture_spec_ref.ref_id)
        evidence_record_refs.append(
            ExperimentEvidenceRecordReferenceModel(
                ref_kind="evidence-record",
                ref_id=record.evidence_record_id,
                ref_version=record.record_version,
            )
        )
    return ExperimentRunTraceabilityModel(
        capture_spec_refs=capture_spec_refs,
        evidence_record_refs=evidence_record_refs,
        notes=[f"Run provenance for attempt {attempt_id}."],
    )


def build_result_summaries(
    outcome: TrialOutcome | None,
    resolution: TerminalCauseResolution,
    lifecycle: _LifecycleEvidence,
) -> dict[str, ExperimentResultSummaryModel]:
    """Return the result summaries recorded for the run.

    The evaluator's summaries are recorded VERBATIM — their concrete evidence
    references are preserved, never rewritten to point at the lifecycle
    attestation. The RAES seal gate rejects any summary whose evidence ref
    does not resolve to a sealed evidence artifact, so a dangling or
    unsupported reference fails the seal rather than being papered over
    (ADR boundary: APTL records evaluator-supplied results; it never attaches
    evidence merely to satisfy a constraint). A run with no evaluator result
    records only the executor's own lifecycle-terminal-cause metric, which
    legitimately cites the lifecycle attestation it actually observes.
    """
    if outcome is not None and outcome.result_summaries:
        return validate_result_summaries(outcome.result_summaries)
    anchor = ExperimentRunEvidenceArtifactReferenceModel(
        ref_kind="evidence", ref_id=lifecycle.artifact.artifact_id
    )
    return {
        "lifecycle-outcome": ExperimentResultSummaryModel(
            metric_id="aptl.lifecycle.terminal-cause",
            value_status="not-applicable",
            evidence_refs=[anchor],
            notes=f"No evaluator result; terminal cause {resolution.cause}.",
        )
    }


def assemble_context(
    store: LocalRunStore, clock: ClockProvider, inputs: AssemblyInputs
) -> TerminalAttemptContext:
    """Assemble the immutable terminal-attempt context for one executed trial."""
    admitted = inputs.admitted
    planned_trial = inputs.planned_trial
    attempt_id = inputs.attempt_id
    scope = inputs.scope
    acquisition = inputs.acquisition
    outcome = inputs.outcome
    resolution = inputs.resolution
    started_at = inputs.started_at
    ended_at = inputs.ended_at

    lifecycle = write_lifecycle_evidence(
        store, attempt_id=attempt_id, scope=scope, resolution=resolution, ended_at=ended_at
    )

    evidence_artifacts = (lifecycle.artifact, *evidence_artifacts_from_acquisition(acquisition))
    # Seal every referenced evidence record AND its content blob: the
    # lifecycle attestation (blob + record) plus each acquisition blob and
    # its persisted record ledger. The traceability names these records, so
    # they must all live in the closed seal inventory.
    sealed_artifacts = (
        lifecycle.sealed_spec,
        lifecycle.record_spec,
        *sealed_artifacts_from_acquisition(acquisition),
        *acquisition_record_specs(acquisition),
    )
    traceability = build_traceability(lifecycle, acquisition, attempt_id)
    result_summaries = build_result_summaries(outcome, resolution, lifecycle)
    deviations = outcome.deviations if outcome else ()

    # Participant provenance is per-attempt: the RAES run model requires its
    # run_id to equal the attempt's run_id, so stamp the attempt identity
    # onto the admitted template.
    participant_provenance = admitted.participant_provenance
    if participant_provenance is not None:
        participant_provenance = participant_provenance.model_copy(
            update={"run_id": attempt_id}
        )

    return TerminalAttemptContext(
        attempt_id=attempt_id,
        run_version=admitted.run_version,
        terminal_cause=resolution.cause,  # type: ignore[arg-type]
        task=admitted.task,
        scenario_snapshot_ref=admitted.scenario_snapshot_ref,
        apparatus_context=admitted.apparatus_context,
        parameter_set=parameter_set_from_trial(planned_trial),
        stochastic_controls=stochastic_controls_from_trial(planned_trial),
        clock_context=clock_context_from_provider(clock),
        traceability=traceability,
        evidence_artifacts=evidence_artifacts,
        result_summaries=result_summaries,
        started_at=started_at,
        ended_at=ended_at,
        participant_implementation_provenance=participant_provenance,
        evaluator_outcome=resolution.evaluator_outcome,
        deviations=tuple(deviations),
        invalidation_reason=resolution.invalidation_reason,
        invalidated_at=ended_at if resolution.invalidation_reason else None,
        sealed_artifacts=sealed_artifacts,
    )
