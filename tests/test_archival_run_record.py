"""RAES ``experiment-run/v1`` composition from a terminal-attempt context
(EXP-009 / ADR-050).

The composer assembles the public ``ExperimentRunModel`` from owner-native
sub-models, applies the terminal-cause status policy, wires invalidation and
retry lineage, and runs every applicable public cross-artifact validator before
the record can be sealed. It never restates RAES field validation and never
forces ``run_status="sealed"``.
"""

from __future__ import annotations

import dataclasses

import pytest
from pydantic import ValidationError
from raes_contracts.contracts import (
    ExperimentReferenceModel,
    ExperimentRunModel,
    ExperimentResultSummaryModel,
    validate_experiment_run_against_task,
)
from raes_contracts.contracts.experiment_manifest_references import (
    ExperimentRunEvidenceArtifactReferenceModel,
)

from tests.archival_fixtures import completed_context, reference_task
from aptl.core.archival.run_record import build_experiment_run_model
from aptl.core.archival.status import TerminalCause


class TestCompletedComposition:
    def test_completed_run_validates_against_task(self) -> None:
        context = completed_context()
        run = build_experiment_run_model(context)
        assert isinstance(run, ExperimentRunModel)
        assert run.schema_version == "experiment-run/v1"
        assert run.run_id == context.attempt_id
        assert run.run_status == "completed"
        assert run.outcome_status == "succeeded"
        # The composer already ran this, but prove the seal-gate invariant holds.
        validate_experiment_run_against_task(reference_task(), run)

    def test_task_ref_is_derived_from_the_task(self) -> None:
        run = build_experiment_run_model(completed_context())
        task = reference_task()
        assert run.task_ref.ref_id == task.task_id
        assert run.task_ref.ref_version == task.task_version


class TestTerminalStatusWiring:
    def test_scenario_failure_maps_to_failed(self) -> None:
        run = build_experiment_run_model(
            completed_context(
                terminal_cause=TerminalCause.SCENARIO_FAILURE, evaluator_outcome=None
            )
        )
        assert run.run_status == "failed"
        assert run.outcome_status == "failed"
        assert run.invalidation is None

    def test_cancellation_maps_to_aborted(self) -> None:
        run = build_experiment_run_model(
            completed_context(
                terminal_cause=TerminalCause.CANCELLATION, evaluator_outcome=None
            )
        )
        assert run.run_status == "aborted"
        assert run.outcome_status == "not-evaluated"

    def test_no_terminal_cause_produces_sealed_run_status(self) -> None:
        invalidating = {TerminalCause.CAPTURE_LOSS, TerminalCause.VALIDITY_FAILURE}
        for cause in TerminalCause:
            evaluator_outcome = (
                "succeeded" if cause is TerminalCause.COMPLETED else None
            )
            reason = "required capture loss" if cause in invalidating else None
            run = build_experiment_run_model(
                completed_context(
                    terminal_cause=cause,
                    evaluator_outcome=evaluator_outcome,
                    invalidation_reason=reason,
                )
            )
            assert run.run_status != "sealed"


class TestInvalidation:
    def test_capture_loss_invalidates_with_invalidation_block(self) -> None:
        run = build_experiment_run_model(
            completed_context(
                terminal_cause=TerminalCause.CAPTURE_LOSS,
                evaluator_outcome=None,
                invalidation_reason="required mid-run capture loss",
            )
        )
        assert run.run_status == "invalidated"
        assert run.invalidation is not None
        assert run.invalidation.reason == "required mid-run capture loss"
        # Defaults invalidated_at to ended_at when unset.
        assert run.invalidation.invalidated_at == run.ended_at

    def test_invalidated_run_requires_a_reason(self) -> None:
        context = completed_context(
            terminal_cause=TerminalCause.CAPTURE_LOSS,
            evaluator_outcome=None,
            invalidation_reason=None,
        )
        with pytest.raises(ValueError, match="invalidation reason"):
            build_experiment_run_model(context)

    def test_invalidation_carries_superseded_by_when_supplied(self) -> None:
        successor = ExperimentReferenceModel(ref_kind="run", ref_id="attempt-retry-2")
        run = build_experiment_run_model(
            completed_context(
                terminal_cause=TerminalCause.VALIDITY_FAILURE,
                evaluator_outcome=None,
                invalidation_reason="unacceptable clock skew",
                superseded_by=successor,
            )
        )
        assert run.invalidation.superseded_by == successor


class TestRetryLineage:
    def test_predecessor_run_ref_folds_into_derived_from_refs(self) -> None:
        predecessor = ExperimentReferenceModel(
            ref_kind="run", ref_id="attempt-original-1", ref_version="1.0.0"
        )
        run = build_experiment_run_model(
            completed_context(predecessor_run_ref=predecessor)
        )
        assert predecessor in run.derived_from_refs


class TestCrossArtifactValidationGate:
    def test_result_summary_without_matching_evidence_artifact_is_rejected(self) -> None:
        """A reported result must cite a concrete evidence artifact (criterion C)."""
        dangling = ExperimentResultSummaryModel(
            metric_id="foothold-achieved",
            value=True,
            value_status="reported",
            evidence_refs=[
                ExperimentRunEvidenceArtifactReferenceModel(
                    ref_kind="evidence", ref_id="does-not-exist"
                )
            ],
        )
        context = completed_context(
            result_summaries={"foothold-achieved-result": dangling}
        )
        with pytest.raises(ValidationError):
            build_experiment_run_model(context)

    def test_ended_before_started_is_rejected(self) -> None:
        context = completed_context(
            started_at="2026-05-26T00:40:00Z", ended_at="2026-05-26T00:10:00Z"
        )
        with pytest.raises(ValidationError):
            build_experiment_run_model(context)
