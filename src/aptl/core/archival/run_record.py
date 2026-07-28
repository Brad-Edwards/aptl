"""Compose the public RAES ``experiment-run/v1`` record for a terminal attempt
(EXP-009 / ADR-050 "Compose public RAES records; do not mirror them").

:func:`build_experiment_run_model` assembles the owner-native sub-models carried
by a :class:`~aptl.core.archival.context.TerminalAttemptContext` into the
top-level ``ExperimentRunModel``, applies the single terminal-cause status
policy, wires the invalidation block and retry lineage, and then runs every
applicable public cross-artifact validator. A record that fails any RAES
validator cannot be sealed (ADR-050: "Do not seal when task/run cross-artifact
validation fails"). This module adds no APTL mirror of any RAES field and never
forces ``run_status="sealed"`` — the seal state is the ADR-050 commit marker.
"""

from __future__ import annotations

from raes_contracts.contracts import (
    ExperimentInvalidationModel,
    ExperimentReferenceModel,
    ExperimentRunModel,
    ExperimentTaskReferenceModel,
    validate_experiment_run_against_task,
    validate_experiment_run_archival_datetimes,
    validate_experiment_run_time_model,
)

from aptl.core.archival.context import TerminalAttemptContext
from aptl.core.archival.status import TerminalStatus, map_terminal_cause

#: The portable run-record schema this composer targets. Read tests pin it to the
#: installed contract's ``EXPERIMENT_RUN_SCHEMA_VERSION``.
RUN_SCHEMA_VERSION = "experiment-run/v1"


def build_experiment_run_model(context: TerminalAttemptContext) -> ExperimentRunModel:
    """Return the validated ``ExperimentRunModel`` for ``context``.

    Raises :class:`ValueError` for an invalidated run missing its reason, and the
    RAES model / cross-artifact validators' errors when the composed record is
    not conformant.
    """
    status = map_terminal_cause(
        context.terminal_cause, evaluator_outcome=context.evaluator_outcome
    )
    invalidation = _build_invalidation(context, status)
    task_ref = ExperimentTaskReferenceModel(
        ref_kind="task",
        ref_id=context.task.task_id,
        ref_version=context.task.task_version,
    )
    derived_from_refs = _fold_predecessor(
        context.predecessor_run_ref, context.derived_from_refs
    )

    run = ExperimentRunModel(
        schema_version=RUN_SCHEMA_VERSION,
        run_id=context.attempt_id,
        run_version=context.run_version,
        task_ref=task_ref,
        scenario_snapshot_ref=context.scenario_snapshot_ref,
        apparatus_context=context.apparatus_context,
        participant_implementation_provenance=context.participant_implementation_provenance,
        parameter_set=list(context.parameter_set),
        realized_bindings=list(context.realized_bindings),
        stochastic_controls=list(context.stochastic_controls),
        stochastic_draws=list(context.stochastic_draws),
        started_at=context.started_at,
        ended_at=context.ended_at,
        clock_context=context.clock_context,
        realized_time_model=context.realized_time_model,
        run_status=status.run_status,
        outcome_status=status.outcome_status,
        traceability=context.traceability,
        realized_form_disclosures=list(context.realized_form_disclosures),
        augmentation_disclosures=list(context.augmentation_disclosures),
        evidence_artifacts=list(context.evidence_artifacts),
        result_summaries=dict(context.result_summaries),
        deviations=list(context.deviations),
        invalidation=invalidation,
        used_refs=list(context.used_refs),
        generated_refs=list(context.generated_refs),
        derived_from_refs=derived_from_refs,
    )

    _run_cross_artifact_validators(run, context)
    return run


def _build_invalidation(
    context: TerminalAttemptContext, status: TerminalStatus
) -> ExperimentInvalidationModel | None:
    """Return the invalidation block iff the terminal status demands it.

    ADR-050 maps capture loss / validity failure to ``run_status="invalidated"``,
    which the RAES model requires to carry an :class:`ExperimentInvalidationModel`.
    A reason is mandatory — the archival layer never fabricates one.
    """
    if not status.requires_invalidation:
        return None
    if not context.invalidation_reason:
        raise ValueError(
            "an invalidated run requires a concrete invalidation reason; the "
            "archival layer never fabricates one"
        )
    return ExperimentInvalidationModel(
        invalidated_at=context.invalidated_at or context.ended_at,
        reason=context.invalidation_reason,
        superseded_by=context.superseded_by,
    )


def _fold_predecessor(
    predecessor: ExperimentReferenceModel | None,
    derived_from_refs: tuple[ExperimentReferenceModel, ...],
) -> list[ExperimentReferenceModel]:
    """Fold a retry's predecessor run reference into ``derived_from_refs``.

    ADR-050: retry lineage uses RAES run references, not a local ``retry_of``
    field. A predecessor already present is not duplicated.
    """
    refs = list(derived_from_refs)
    if predecessor is not None and predecessor not in refs:
        refs.append(predecessor)
    return refs


def _run_cross_artifact_validators(
    run: ExperimentRunModel, context: TerminalAttemptContext
) -> None:
    """Run every applicable public RAES cross-artifact validator (the seal gate).

    These check facts a single model's ``extra="forbid"`` validation cannot see:
    task/scenario/apparatus/metric/evidence agreement, archival datetimes, and —
    for a governed scenario — the realized time model. Local validation may add
    archive-bounds/containment checks on top, but never restates these.
    """
    validate_experiment_run_against_task(context.task, run)
    validate_experiment_run_archival_datetimes(run)
    if context.time_model_declaration is not None:
        validate_experiment_run_time_model(run, context.time_model_declaration)
