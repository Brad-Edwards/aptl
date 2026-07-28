"""Integration: the execution controller drives admitted trials to a sealed
record through the production path (#437/#459 → EXP-009 / ADR-050).

This is the production-path integration the codex review required: a real
`ExperimentExecutor` composes the public RAES run record, runs the RAES
cross-artifact validators, and seals — reaching `finalize_terminal_attempt` for
every terminal cause. The participant workload and collectors are injected (the
same seam `acquire_evidence` uses for `trial_body`); everything downstream is the
real archival seal path.
"""

from __future__ import annotations

import json

import pytest
from raes_contracts.contracts import (
    ExperimentApparatusConstraintModel,
    ExperimentEvaluationProtocolModel,
    ExperimentEvidenceReferenceModel,
    ExperimentMetricDefinitionModel,
    ExperimentResultSummaryModel,
    ExperimentRunModel,
    ExperimentScenarioReferenceModel,
    ExperimentSplitAndLeakageControlsModel,
    ExperimentTaskModel,
    ExperimentValidityNoteModel,
)
from raes_contracts.contracts.experiment_manifest_references import (
    ExperimentRunEvidenceArtifactReferenceModel,
)

from tests.archival_fixtures import reference_run
from aptl.core.archival.layout import RUN_MANIFEST_RELPATH
from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult, AcquisitionDisposition
from aptl.core.execution.executor import (
    LIFECYCLE_OBSERVATION_REF,
    AdmittedExperiment,
    ExperimentExecutor,
    TrialOutcome,
    TrialTerminalSignal,
)
from aptl.core.experiment.policy import OrderingKind
from aptl.core.experiment.trial_plan_models import PlannedTrial, TrialPlan
from aptl.core.runstore import LocalRunStore

_CLOCK = FixedClockProvider(measurement_time="2026-05-26T00:10:00Z")


def _minimal_task() -> ExperimentTaskModel:
    ref = ExperimentEvidenceReferenceModel(ref_kind="evidence", ref_id=LIFECYCLE_OBSERVATION_REF)
    return ExperimentTaskModel(
        schema_version="experiment-task/v1",
        task_id="task-aptl-exec-it",
        task_version="1.0.0",
        title="APTL execution integration task",
        description="Minimal task exercised by the execution-controller integration test.",
        scenario_ref=ExperimentScenarioReferenceModel(
            ref_kind="scenario-snapshot",
            ref_id="scenario-techvault",
            ref_version="2026-05-26",
            ref_digest="sha256:" + "1" * 64,
        ),
        evaluation_protocol=ExperimentEvaluationProtocolModel(
            protocol_id="proto-aptl-exec",
            protocol_version="1.0.0",
            intent="record the terminal outcome of each attempt",
            unit_of_analysis="run",
            metric_definitions={
                "aptl.lifecycle.terminal-cause": ExperimentMetricDefinitionModel(
                    metric_id="aptl.lifecycle.terminal-cause",
                    metric_version="1.0.0",
                    name="Terminal cause",
                    measured_construct="run terminal state",
                    unit_of_analysis="run",
                    value_kind="text",
                    direction="descriptive",
                    evidence_requirements=[ref],
                )
            },
            observation_requirements=[ref],
        ),
        intended_use="integration testing of the execution controller",
        population_or_construct="terminal execution attempts",
        split_and_leakage_controls=ExperimentSplitAndLeakageControlsModel(
            hidden_material_policy="No hidden material in this integration task."
        ),
        apparatus_constraints=ExperimentApparatusConstraintModel(
            notes=["No apparatus constraints beyond admission for this task."]
        ),
        validity_notes=[
            ExperimentValidityNoteModel(category="apparatus", note="Minimal integration task.")
        ],
        artifact_refs=[reference_run().apparatus_context.observed_setup_evidence[0]],
    )


def _admitted() -> AdmittedExperiment:
    run = reference_run()
    trial = PlannedTrial(
        planned_trial_id="trial-0001",
        condition_id="baseline",
        replication_ordinal=0,
        ordering_index=0,
        factor_levels=(),
        parameter_bindings=(("difficulty", "standard"),),
        stochastic_seeds=(("task-seed", "12345"),),
        scenario_snapshot_digest=None,
        capture_spec_refs=(),
    )
    plan = TrialPlan(
        plan_id="plan-exec-it",
        policy_version="v1",
        source_set_digest="sha256:" + "2" * 64,
        ordering_kind=OrderingKind.FLAT,
        trials=(trial,),
        capture_bindings=(),
        canonical_bytes=b"{}",
        plan_digest="sha256:" + "3" * 64,
    )
    return AdmittedExperiment(
        plan=plan,
        task=_minimal_task(),
        scenario_snapshot_ref=run.scenario_snapshot_ref,
        apparatus_context=run.apparatus_context,
        participant_provenance=run.participant_implementation_provenance,
    )


def _completed_workload(_ctx):
    # The evaluator cites a real, sealed evidence artifact (the lifecycle
    # attestation); the executor records the reference verbatim.
    return TrialOutcome(
        signal=TrialTerminalSignal.COMPLETED,
        evaluator_outcome="succeeded",
        result_summaries={
            "terminal-cause": ExperimentResultSummaryModel(
                metric_id="aptl.lifecycle.terminal-cause",
                value="completed",
                value_status="reported",
                evidence_refs=[
                    ExperimentRunEvidenceArtifactReferenceModel(
                        ref_kind="evidence", ref_id="lifecycle-attempt-record"
                    )
                ],
            )
        },
    )


def _store(tmp_path) -> LocalRunStore:
    return LocalRunStore(tmp_path / "runs")


class TestProductionSealPath:
    def test_completed_attempt_seals_a_conformant_record(self, tmp_path):
        store = _store(tmp_path)
        executor = ExperimentExecutor(
            store=store, clock=_CLOCK, collectors={}, workload=_completed_workload
        )
        result = executor.execute_trial(_admitted(), _admitted().plan.trials[0])

        assert result.run.run_status == "completed"
        assert result.run.outcome_status == "succeeded"
        assert store.is_sealed(result.run.run_id)
        manifest = json.loads(
            (store.get_run_path(result.run.run_id) / RUN_MANIFEST_RELPATH).read_text()
        )
        ExperimentRunModel.model_validate(manifest)

    def test_execute_seals_every_trial_once(self, tmp_path):
        store = _store(tmp_path)
        executor = ExperimentExecutor(
            store=store, clock=_CLOCK, collectors={}, workload=_completed_workload
        )
        results = executor.execute(_admitted())
        assert len(results) == 1
        assert all(not r.idempotent for r in results)

    def test_dangling_evaluator_evidence_reference_is_rejected(self, tmp_path):
        """A summary citing an artifact that was never sealed fails the seal."""
        store = _store(tmp_path)

        def dangling_workload(_ctx):
            return TrialOutcome(
                signal=TrialTerminalSignal.COMPLETED,
                evaluator_outcome="succeeded",
                result_summaries={
                    "terminal-cause": ExperimentResultSummaryModel(
                        metric_id="aptl.lifecycle.terminal-cause",
                        value="completed",
                        value_status="reported",
                        evidence_refs=[
                            ExperimentRunEvidenceArtifactReferenceModel(
                                ref_kind="evidence", ref_id="not-a-real-artifact"
                            )
                        ],
                    )
                },
            )

        executor = ExperimentExecutor(
            store=store, clock=_CLOCK, collectors={}, workload=dangling_workload
        )
        with pytest.raises(Exception):  # noqa: B017 - RAES ValidationError
            executor.execute_trial(_admitted(), _admitted().plan.trials[0])
        assert not store.is_sealed("trial-0001-attempt-1")

    def test_recovers_an_interrupted_attempt(self, tmp_path):
        """An attempt with a durable intent but no seal recovers to interrupted."""
        store = _store(tmp_path)
        admitted = _admitted()
        trial = admitted.plan.trials[0]
        # Simulate a crash mid-workload: the intent is written, nothing sealed.
        attempt_id = "trial-0001-attempt-1"
        store.create_run(attempt_id)
        store.create_run_json_once(
            attempt_id,
            "attempt-intent.json",
            {
                "schema_version": "aptl.attempt-intent/v1",
                "attempt_id": attempt_id,
                "planned_trial_id": trial.planned_trial_id,
                "plan_id": admitted.plan.plan_id,
                "plan_digest": admitted.plan.plan_digest,
                "started_at": "2026-05-26T00:10:00Z",
            },
        )
        assert not store.is_sealed(attempt_id)

        executor = ExperimentExecutor(
            store=store, clock=_CLOCK, collectors={}, workload=_completed_workload
        )
        result = executor.recover_interrupted_attempt(admitted, trial, attempt_id)
        assert result is not None
        assert result.run.run_status == "aborted"  # infrastructure interruption
        assert store.is_sealed(attempt_id)
        # Already-sealed / never-started attempts recover to None.
        assert executor.recover_interrupted_attempt(admitted, trial, attempt_id) is None


class TestTerminalCauses:
    @pytest.mark.parametrize(
        ("signal", "expected_status"),
        [
            (TrialTerminalSignal.SCENARIO_FAILURE, "failed"),
            (TrialTerminalSignal.EVALUATOR_FAILURE, "failed"),
            (TrialTerminalSignal.CANCELLED, "aborted"),
            (TrialTerminalSignal.POLICY_STOP, "aborted"),
            (TrialTerminalSignal.INTERRUPTED, "aborted"),
        ],
    )
    def test_failure_and_abort_signals_seal_the_right_status(
        self, tmp_path, signal, expected_status
    ):
        store = _store(tmp_path)

        def workload(_ctx):
            return TrialOutcome(signal=signal)

        executor = ExperimentExecutor(
            store=store, clock=_CLOCK, collectors={}, workload=workload
        )
        result = executor.execute_trial(_admitted(), _admitted().plan.trials[0])
        assert result.run.run_status == expected_status

    def test_workload_exception_seals_an_interruption(self, tmp_path):
        store = _store(tmp_path)

        def boom(_ctx):
            raise RuntimeError("participant crashed")

        executor = ExperimentExecutor(store=store, clock=_CLOCK, collectors={}, workload=boom)
        result = executor.execute_trial(_admitted(), _admitted().plan.trials[0])
        assert result.run.run_status == "aborted"  # infrastructure interruption

    def test_capture_loss_seals_an_invalidated_record(self, tmp_path, monkeypatch):
        store = _store(tmp_path)

        def invalidated_acquire(**_kwargs):
            _kwargs["trial_body"]()  # still run the workload
            return AcquisitionResult(
                disposition=AcquisitionDisposition.INVALIDATED,
                records=(),
                refs=(),
                reports=(),
                diagnostics=(),
            )

        monkeypatch.setattr(
            "aptl.core.execution.executor.acquire_evidence", invalidated_acquire
        )
        executor = ExperimentExecutor(
            store=store, clock=_CLOCK, collectors={}, workload=_completed_workload
        )
        result = executor.execute_trial(_admitted(), _admitted().plan.trials[0])
        assert result.run.run_status == "invalidated"
        assert result.run.invalidation is not None
