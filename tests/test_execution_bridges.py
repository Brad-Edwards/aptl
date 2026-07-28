"""Owner-native -> RAES sub-model bridges + terminal-cause normalization
(#437/#459 → EXP-009)."""

from __future__ import annotations

from aptl.core.correlation.clock import FixedClockProvider
from aptl.core.evidence.coordinator import AcquisitionResult
from aptl.core.evidence.outcomes import AcquisitionDisposition
from aptl.core.execution.bridges import (
    clock_context_from_provider,
    parameter_set_from_trial,
    stochastic_controls_from_trial,
    validate_result_summaries,
)
from aptl.core.execution.executor import (
    TrialOutcome,
    TrialTerminalSignal,
    normalize_terminal_cause,
)
from aptl.core.archival.status import TerminalCause
from aptl.core.experiment.trial_plan_models import PlannedTrial


def _trial(**overrides) -> PlannedTrial:
    base = dict(
        planned_trial_id="t1",
        condition_id="c1",
        replication_ordinal=0,
        ordering_index=0,
        factor_levels=(),
        parameter_bindings=(),
        stochastic_seeds=(),
        scenario_snapshot_digest=None,
        capture_spec_refs=(),
    )
    base.update(overrides)
    return PlannedTrial(**base)


class TestClockBridge:
    def test_host_utc_maps_to_wall_clock(self):
        clock = FixedClockProvider(measurement_time="2026-05-26T00:00:00Z")
        ctx = clock_context_from_provider(clock)
        assert ctx.time_domain == "wall-clock"
        assert ctx.synchronization == "unknown"
        assert ctx.authority == "fixed"

    def test_unknown_domain_maps_to_other(self):
        clock = FixedClockProvider(
            measurement_time="2026-05-26T00:00:00Z", timestamp_domain="quantum"
        )
        assert clock_context_from_provider(clock).time_domain == "other"


class TestParameterBridge:
    def test_projects_bindings(self):
        params = parameter_set_from_trial(
            _trial(parameter_bindings=(("difficulty", "hard"), ("workers", 4)))
        )
        assert {p.name for p in params} == {"difficulty", "workers"}

    def test_falls_back_to_condition_when_empty(self):
        params = parameter_set_from_trial(_trial(condition_id="baseline", parameter_bindings=()))
        assert len(params) == 1
        assert params[0].value == "baseline"

    def test_non_scalar_binding_is_stringified(self):
        params = parameter_set_from_trial(_trial(parameter_bindings=(("obj", {"a": 1}),)))
        assert isinstance(params[0].value, str)


class TestStochasticBridge:
    def test_projects_seeds(self):
        controls = stochastic_controls_from_trial(
            _trial(stochastic_seeds=(("task-seed", "42"),))
        )
        assert controls[0].control_id == "task-seed"
        assert controls[0].role == "seed"

    def test_falls_back_when_empty(self):
        controls = stochastic_controls_from_trial(_trial(stochastic_seeds=()))
        assert len(controls) == 1
        assert controls[0].control_id == "deterministic"


class TestResultSummaryGuard:
    def test_rejects_non_result_summary(self):
        import pytest

        with pytest.raises(TypeError):
            validate_result_summaries({"x": "not a summary"})  # type: ignore[dict-item]


def _acq(disposition: AcquisitionDisposition) -> AcquisitionResult:
    return AcquisitionResult(
        disposition=disposition, records=(), refs=(), reports=(), diagnostics=()
    )


class TestApparatusContextBridge:
    def test_builds_a_valid_apparatus_context(self):
        from raes_contracts.contracts import ExperimentApparatusContextModel

        from aptl.core.execution.apparatus import ApparatusInputs, build_apparatus_context

        clock = clock_context_from_provider(
            FixedClockProvider(measurement_time="2026-05-26T00:00:00Z")
        )
        ctx = build_apparatus_context(
            ApparatusInputs(
                apparatus_context_id="apparatus-aptl",
                declared_at="2026-05-26T00:00:00Z",
                clock=clock,
                participant=("reference-red-agent", "1.0.0"),
            )
        )
        # Round-trips through the installed contract model with participant.
        ExperimentApparatusContextModel.model_validate(ctx.model_dump(mode="json"))
        assert set(ctx.components) == {"processor", "backend", "participant"}

    def test_without_participant_has_two_components(self):
        from aptl.core.execution.apparatus import ApparatusInputs, build_apparatus_context

        clock = clock_context_from_provider(
            FixedClockProvider(measurement_time="2026-05-26T00:00:00Z")
        )
        ctx = build_apparatus_context(
            ApparatusInputs(
                apparatus_context_id="apparatus-aptl",
                declared_at="2026-05-26T00:00:00Z",
                clock=clock,
            )
        )
        assert set(ctx.components) == {"processor", "backend"}


class TestTerminalCauseNormalization:
    def test_invalidated_disposition_dominates(self):
        outcome = TrialOutcome(signal=TrialTerminalSignal.COMPLETED, evaluator_outcome="succeeded")
        res = normalize_terminal_cause(outcome, AcquisitionDisposition.INVALIDATED)
        assert res.cause is TerminalCause.CAPTURE_LOSS
        assert res.invalidation_reason

    def test_missing_outcome_is_interruption(self):
        res = normalize_terminal_cause(None, AcquisitionDisposition.SEALED_READY)
        assert res.cause is TerminalCause.INFRASTRUCTURE_INTERRUPTION

    def test_completed_carries_evaluator_outcome(self):
        outcome = TrialOutcome(signal=TrialTerminalSignal.COMPLETED, evaluator_outcome="partial")
        res = normalize_terminal_cause(outcome, AcquisitionDisposition.SEALED_READY)
        assert res.cause is TerminalCause.COMPLETED
        assert res.evaluator_outcome == "partial"

    def test_inconclusive_acquisition_is_interruption(self):
        outcome = TrialOutcome(signal=TrialTerminalSignal.COMPLETED, evaluator_outcome="succeeded")
        res = normalize_terminal_cause(outcome, AcquisitionDisposition.INCONCLUSIVE)
        assert res.cause is TerminalCause.INFRASTRUCTURE_INTERRUPTION

    def test_workload_failure_signals_map(self):
        for signal, expected in [
            (TrialTerminalSignal.SCENARIO_FAILURE, TerminalCause.SCENARIO_FAILURE),
            (TrialTerminalSignal.EVALUATOR_FAILURE, TerminalCause.EVALUATOR_FAILURE),
            (TrialTerminalSignal.CANCELLED, TerminalCause.CANCELLATION),
            (TrialTerminalSignal.POLICY_STOP, TerminalCause.POLICY_STOP),
            (TrialTerminalSignal.INTERRUPTED, TerminalCause.INFRASTRUCTURE_INTERRUPTION),
        ]:
            res = normalize_terminal_cause(
                TrialOutcome(signal=signal), AcquisitionDisposition.SEALED_READY
            )
            assert res.cause is expected
