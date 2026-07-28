"""The live execution controller (#437/#459) that drives admitted trials to a
sealed terminal record (EXP-009 / ADR-050).

:class:`ExperimentExecutor` is the production terminal-attempt authority ADR-050
reserves for #437/#459. For each planned trial it:

1. allocates a distinct ``attempt_id`` (the portable ``run_id``);
2. runs the injected workload (participant actions + evaluation) as the evidence
   coordinator's ``trial_body``, so collectors are live during the trial;
3. normalizes the terminal cause from the workload signal and the acquisition
   disposition (a ``finally`` boundary maps an exception/cancellation to an
   interruption);
4. always records the attempt's own terminal attestation as lifecycle evidence,
   so the RAES run's mandatory evidence/traceability/result fields are satisfied
   even when an authored collector never started;
5. assembles the owner-native :class:`TerminalAttemptContext` and calls
   :func:`finalize_terminal_attempt` exactly once.

The workload and collectors are injected — participant execution and evaluation
are lab/RAES-runtime concerns, the same seam ``acquire_evidence`` already uses
for ``trial_body``. The executor itself does the real archival work; it defines
no metrics and derives no results.
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
from aptl.core.archival.coordinator import SealResult, finalize_terminal_attempt
from aptl.core.archival.seal import SealedArtifactSpec
from aptl.core.archival.status import TerminalCause
from aptl.core.correlation.clock import ClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult, acquire_evidence
from aptl.core.evidence.outcomes import AcquisitionDisposition
from aptl.core.evidence.protocol import Collector, RunScope
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
from aptl.utils.logging import get_logger

log = get_logger("execution.executor")

_LIFECYCLE_ARTIFACT_ID = "lifecycle-attempt-record"
_LIFECYCLE_CAPTURE_SPEC = "aptl.lifecycle"
_LIFECYCLE_SUBDIR = "lifecycle"
_LIFECYCLE_MAX_BYTES = 64 * 1024
#: Run-relative subdirectory of the create-once evidence-record ledger (matches
#: the evidence coordinator's ``_LEDGER_SUBDIR``).
_EVIDENCE_LEDGER_SUBDIR = "evidence/records"
#: Run-relative path of the durable attempt-intent journal, written create-once
#: before the workload so an interrupted attempt is recoverable.
_ATTEMPT_INTENT_RELPATH = "attempt-intent.json"

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


def normalize_terminal_cause(
    outcome: TrialOutcome | None, disposition: AcquisitionDisposition
) -> "TerminalCauseResolution":
    """Resolve the terminal cause from the workload signal and evidence disposition.

    Evidence invalidation dominates (a lost required capture invalidates the run
    regardless of the workload); otherwise a workload failure/abort wins; an
    inconclusive acquisition (a required source never started) is an
    infrastructure interruption; a clean completion with intact evidence is a
    completion. A missing outcome (the workload raised or was cancelled before
    reporting) is an infrastructure interruption.
    """
    if disposition is AcquisitionDisposition.INVALIDATED:
        reason = (outcome.invalidation_reason if outcome else None) or (
            "required evidence was lost during the run"
        )
        return TerminalCauseResolution(TerminalCause.CAPTURE_LOSS, invalidation_reason=reason)
    cause = _resolve_non_invalidated_cause(outcome, disposition)
    evaluator_outcome = (
        outcome.evaluator_outcome
        if outcome is not None and cause is TerminalCause.COMPLETED
        else None
    )
    return TerminalCauseResolution(cause, evaluator_outcome=evaluator_outcome)


def _resolve_non_invalidated_cause(
    outcome: TrialOutcome | None, disposition: AcquisitionDisposition
) -> TerminalCause:
    """Resolve the terminal cause when evidence was not invalidated."""
    if outcome is None:
        return TerminalCause.INFRASTRUCTURE_INTERRUPTION
    mapped = _SIGNAL_CAUSE_MAP.get(outcome.signal)
    if mapped is not None:
        return mapped
    # A completed workload: an inconclusive acquisition (a required source never
    # started) is an interruption; intact evidence is a completion.
    return (
        TerminalCause.INFRASTRUCTURE_INTERRUPTION
        if disposition is AcquisitionDisposition.INCONCLUSIVE
        else TerminalCause.COMPLETED
    )


@dataclass(frozen=True)
class TerminalCauseResolution:
    """A resolved terminal cause plus the fields it implies."""

    cause: object  # TerminalCause (imported lazily to avoid a heavy import here)
    evaluator_outcome: str | None = None
    invalidation_reason: str | None = None


@dataclass
class ExperimentExecutor:
    """Drives an :class:`AdmittedExperiment` to sealed terminal records."""

    store: LocalRunStore
    clock: ClockProvider
    collectors: Mapping[str, Collector]
    workload: Workload
    attempt_id_factory: Callable[[PlannedTrial, int], str] = (
        lambda trial, ordinal: f"{trial.planned_trial_id}-attempt-{ordinal}"
    )

    def execute(self, admitted: AdmittedExperiment) -> list[SealResult]:
        """Execute every planned trial once, returning one seal result per attempt."""
        return [self.execute_trial(admitted, trial) for trial in admitted.plan.trials]

    def execute_trial(
        self, admitted: AdmittedExperiment, planned_trial: PlannedTrial, *, attempt_ordinal: int = 1
    ) -> SealResult:
        """Execute one planned trial once and seal its terminal record."""
        attempt_id = self.attempt_id_factory(planned_trial, attempt_ordinal)
        scope = RunScope(
            run_id=attempt_id,
            planned_trial_id=planned_trial.planned_trial_id,
            attempt_id=attempt_id,
        )
        self.store.create_run(attempt_id)
        started_at = self.clock.now()
        # Durably bind the attempt to its admitted trial BEFORE running the
        # workload, so a crash / host restart / non-returning cancellation leaves
        # a recoverable intent (recover_interrupted_attempt) rather than an
        # untracked run.
        self._write_attempt_intent(admitted, planned_trial, attempt_id, started_at)

        trial_context = TrialExecutionContext(attempt_id, planned_trial, scope)
        holder: dict[str, TrialOutcome] = {}
        ran: dict[str, bool] = {"done": False}

        def trial_body() -> None:
            holder["outcome"] = self.workload(trial_context)
            ran["done"] = True

        acquisition = acquire_evidence(
            bindings=admitted.plan.capture_bindings,
            collectors=self.collectors,
            run_store=self.store,
            scope=scope,
            clock=self.clock,
            trial_body=trial_body,
        )
        # ``acquire_evidence`` runs the trial body only while collectors are live.
        # When the plan declares no captures there is nothing to capture, so the
        # trial still runs — here, outside a (non-existent) capture window. A
        # plan that DID declare captures but whose collectors never started is a
        # genuine infrastructure interruption; the trial body correctly did not
        # run and ``outcome`` stays ``None``.
        if not ran["done"] and not admitted.plan.capture_bindings:
            try:
                holder["outcome"] = self.workload(trial_context)
            except Exception:  # noqa: BLE001 - a crashed trial is a terminal cause, not a bug
                log.warning("trial workload raised for attempt %s", attempt_id)
        ended_at = self.clock.now()
        outcome = holder.get("outcome")
        resolution = normalize_terminal_cause(outcome, acquisition.disposition)

        context = self._assemble_context(
            admitted=admitted,
            planned_trial=planned_trial,
            attempt_id=attempt_id,
            scope=scope,
            acquisition=acquisition,
            outcome=outcome,
            resolution=resolution,
            started_at=started_at,
            ended_at=ended_at,
        )
        result = finalize_terminal_attempt(context, store=self.store)
        log.info(
            "executed and sealed attempt %s (cause=%s, run_status=%s)",
            attempt_id,
            resolution.cause,
            result.run.run_status,
        )
        return result

    def _write_attempt_intent(
        self,
        admitted: AdmittedExperiment,
        planned_trial: PlannedTrial,
        attempt_id: str,
        started_at: str,
    ) -> None:
        """Persist the bounded, immutable attempt intent create-once."""
        self.store.create_run_json_once(
            attempt_id,
            _ATTEMPT_INTENT_RELPATH,
            {
                "schema_version": "aptl.attempt-intent/v1",
                "attempt_id": attempt_id,
                "planned_trial_id": planned_trial.planned_trial_id,
                "plan_id": admitted.plan.plan_id,
                "plan_digest": admitted.plan.plan_digest,
                "started_at": started_at,
            },
        )

    def recover_interrupted_attempt(
        self, admitted: AdmittedExperiment, planned_trial: PlannedTrial, attempt_id: str
    ) -> SealResult | None:
        """Convert an unfinished attempt into a sealed interruption record.

        Returns ``None`` when the attempt has no intent (never started) or is
        already sealed (nothing to recover). Otherwise it seals an
        infrastructure-interruption terminal record for the attempt from its
        durable admitted inputs — the restart path a crash requires.
        """
        if self.store.is_sealed(attempt_id):
            return None
        if self.store.read_run_json(attempt_id, _ATTEMPT_INTENT_RELPATH) is None:
            return None
        scope = RunScope(
            run_id=attempt_id,
            planned_trial_id=planned_trial.planned_trial_id,
            attempt_id=attempt_id,
        )
        now = self.clock.now()
        context = self._assemble_context(
            admitted=admitted,
            planned_trial=planned_trial,
            attempt_id=attempt_id,
            scope=scope,
            acquisition=AcquisitionResult(
                disposition=AcquisitionDisposition.INCONCLUSIVE,
                records=(),
                refs=(),
                reports=(),
                diagnostics=(),
            ),
            outcome=None,
            resolution=normalize_terminal_cause(None, AcquisitionDisposition.INCONCLUSIVE),
            started_at=now,
            ended_at=now,
        )
        return finalize_terminal_attempt(context, store=self.store)

    def _assemble_context(
        self,
        *,
        admitted: AdmittedExperiment,
        planned_trial: PlannedTrial,
        attempt_id: str,
        scope: RunScope,
        acquisition: AcquisitionResult,
        outcome: TrialOutcome | None,
        resolution: TerminalCauseResolution,
        started_at: str,
        ended_at: str,
    ) -> TerminalAttemptContext:
        lifecycle = self._write_lifecycle_evidence(
            attempt_id=attempt_id, scope=scope, resolution=resolution, ended_at=ended_at
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
            *self._acquisition_record_specs(acquisition),
        )
        traceability = self._build_traceability(lifecycle, acquisition, attempt_id)
        result_summaries = self._build_result_summaries(outcome, resolution, lifecycle)
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
            clock_context=clock_context_from_provider(self.clock),
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

    def _write_lifecycle_evidence(
        self, *, attempt_id: str, scope: RunScope, resolution: TerminalCauseResolution, ended_at: str
    ) -> "_LifecycleEvidence":
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
            self.store, attempt_id, [blob], subdir=_LIFECYCLE_SUBDIR, max_bytes=_LIFECYCLE_MAX_BYTES
        )
        digest_hex = hashlib.sha256(blob).hexdigest()
        artifact = ExperimentArtifactRefModel(
            artifact_id=_LIFECYCLE_ARTIFACT_ID,
            role="documentation",
            media_type="application/json",
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
        self.store.create_run_json_once(
            attempt_id, record_relpath, record.model_dump(mode="json", exclude_none=True)
        )
        record_spec = SealedArtifactSpec(
            path=record_relpath, media_type="application/json", role="evidence-record"
        )
        return _LifecycleEvidence(
            artifact=artifact, record=record, sealed_spec=sealed_spec, record_spec=record_spec
        )

    @staticmethod
    def _acquisition_record_specs(
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
                media_type="application/json",
                role="evidence-record",
            )
            for record in acquisition.records
        )

    @staticmethod
    def _build_traceability(
        lifecycle: "_LifecycleEvidence", acquisition: AcquisitionResult, attempt_id: str
    ) -> ExperimentRunTraceabilityModel:
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

    @staticmethod
    def _build_result_summaries(
        outcome: TrialOutcome | None,
        resolution: TerminalCauseResolution,
        lifecycle: "_LifecycleEvidence",
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


@dataclass(frozen=True)
class _LifecycleEvidence:
    artifact: ExperimentArtifactRefModel
    record: ExperimentEvidenceRecordModel
    sealed_spec: SealedArtifactSpec
    record_spec: SealedArtifactSpec
