"""The immutable terminal-attempt handoff (EXP-009 / ADR-050).

:class:`TerminalAttemptContext` is the typed, immutable value-transport the
execution controller (issues #437/#459) hands the archive coordinator exactly
once per terminal attempt. It is **not** a serializable contract and never
mirrors ``ExperimentRunModel`` — it carries owner-native RAES sub-models and the
few APTL identity facts (the distinct ``attempt_id``, the normalized terminal
cause, retry lineage) the coordinator needs to compose and seal the portable run
without rediscovering anything from mutable state.

Per ADR-050 the ``attempt_id`` is a distinct, filesystem-safe identity that IS
the portable ``ExperimentRunModel.run_id`` and the run archive directory name; a
retry reuses the same admitted plan but gets a new ``attempt_id`` and records its
predecessor via ``predecessor_run_ref``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from raes_contracts.contracts import (
    ExperimentApparatusContextModel,
    ExperimentArtifactRefModel,
    ExperimentAugmentationDisclosureModel,
    ExperimentClockContextModel,
    ExperimentParameterModel,
    ExperimentRealizedFormDisclosureModel,
    ExperimentReferenceModel,
    ExperimentResultSummaryModel,
    ExperimentRunTraceabilityModel,
    ExperimentScenarioSnapshotReferenceModel,
    ExperimentStochasticControlModel,
    ExperimentTaskModel,
    ParticipantImplementationProvenanceModel,
    RandomStreamDrawRecordModel,
    RealizedBindingProvenanceModel,
)
from raes_contracts.contracts.time_model import (
    RealizedTimeModelProvenanceModel,
    TimeModelDeclarationModel,
)

from aptl.core.archival.seal import SealLimitation, SealedArtifactSpec
from aptl.core.archival.status import TerminalCause


@dataclass(frozen=True)
class TerminalAttemptContext:
    """Owner-native facts for one terminal execution attempt.

    Every RAES sub-model here is produced by its own owner (apparatus/participant
    provenance, evidence coordinator, evaluator, clock provider); the coordinator
    assembles them into the top-level run record, applies the terminal-cause
    status policy, and seals. ``task`` is the admitted task the run is validated
    against (``validate_experiment_run_against_task``); ``task_ref`` on the run is
    derived from it so the two can never disagree.
    """

    # -- identity and terminal cause --------------------------------------
    attempt_id: str
    run_version: str
    terminal_cause: TerminalCause
    # -- required RAES sub-models -----------------------------------------
    task: ExperimentTaskModel
    scenario_snapshot_ref: ExperimentScenarioSnapshotReferenceModel
    apparatus_context: ExperimentApparatusContextModel
    parameter_set: tuple[ExperimentParameterModel, ...]
    stochastic_controls: tuple[ExperimentStochasticControlModel, ...]
    clock_context: ExperimentClockContextModel
    traceability: ExperimentRunTraceabilityModel
    evidence_artifacts: tuple[ExperimentArtifactRefModel, ...]
    result_summaries: Mapping[str, ExperimentResultSummaryModel]
    started_at: str
    ended_at: str
    # -- optional / defaulted ---------------------------------------------
    #: The evaluator's verdict; REQUIRED when ``terminal_cause`` is COMPLETED and
    #: ignored otherwise. The archival layer never derives an outcome.
    evaluator_outcome: str | None = None
    participant_implementation_provenance: ParticipantImplementationProvenanceModel | None = None
    realized_bindings: tuple[RealizedBindingProvenanceModel, ...] = ()
    stochastic_draws: tuple[RandomStreamDrawRecordModel, ...] = ()
    realized_time_model: RealizedTimeModelProvenanceModel | None = None
    #: Present only for a time-model-governed scenario; drives
    #: ``validate_experiment_run_time_model``.
    time_model_declaration: TimeModelDeclarationModel | None = None
    realized_form_disclosures: tuple[ExperimentRealizedFormDisclosureModel, ...] = ()
    augmentation_disclosures: tuple[ExperimentAugmentationDisclosureModel, ...] = ()
    deviations: tuple[str, ...] = ()
    #: Reason for an invalidated run (capture loss / validity failure). Required
    #: when the terminal cause maps to ``run_status="invalidated"``.
    invalidation_reason: str | None = None
    #: When the invalidation occurred; defaults to ``ended_at`` if unset.
    invalidated_at: str | None = None
    #: The run that replaces an invalidated one (``invalidation.superseded_by``).
    superseded_by: ExperimentReferenceModel | None = None
    #: The predecessor run of a retry; folded into ``derived_from_refs``.
    predecessor_run_ref: ExperimentReferenceModel | None = None
    used_refs: tuple[ExperimentReferenceModel, ...] = ()
    generated_refs: tuple[ExperimentReferenceModel, ...] = ()
    derived_from_refs: tuple[ExperimentReferenceModel, ...] = ()
    #: The already-written run-relative artifacts the seal binds beyond the run
    #: manifest: evidence records/blobs, final provenance, correlation/clock
    #: disclosures, evaluator exports, and required lifecycle evidence. Each is
    #: sealed as-is (the coordinator reads and checksums the bytes; it never
    #: mutates them).
    sealed_artifacts: tuple[SealedArtifactSpec, ...] = ()
    #: Accepted limitations to disclose in the seal's completeness statement
    #: (e.g. a policy-accepted capture degradation or a missing provenance
    #: source). Their fatality was already decided by the readiness policy (#472).
    accepted_limitations: tuple[SealLimitation, ...] = ()
