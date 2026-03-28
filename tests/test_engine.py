"""Tests for the scenario runtime engine."""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aptl.core.engine import ScenarioEngine
from aptl.core.evaluators import EvaluationResult
from aptl.core.scenarios import (
    CommandOutputValidation,
    ContainerRequirements,
    Objective,
    ObjectiveSet,
    ObjectiveType,
    ScenarioDefinition,
    ScenarioMetadata,
    ScenarioMode,
    ScoringConfig,
    WazuhAlertValidation,
)
from aptl.core.session import ScenarioSession


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scenario_with_evaluable() -> ScenarioDefinition:
    """Scenario with both manual and auto-evaluable objectives."""
    return ScenarioDefinition(
        metadata=ScenarioMetadata(
            id="engine-test",
            name="Engine Test",
            description="Test scenario for engine",
            difficulty="beginner",
            estimated_minutes=30,
        ),
        mode=ScenarioMode.PURPLE,
        containers=ContainerRequirements(required=["kali", "victim"]),
        objectives=ObjectiveSet(
            red=[
                Objective(
                    id="manual-obj",
                    description="Manual task",
                    type=ObjectiveType.MANUAL,
                    points=50,
                ),
                Objective(
                    id="cmd-obj",
                    description="Check command output",
                    type=ObjectiveType.COMMAND_OUTPUT,
                    points=100,
                    command_output=CommandOutputValidation(
                        container="kali",
                        command="cat /tmp/flag.txt",
                        contains=["FLAG{test}"],
                    ),
                ),
            ],
            blue=[
                Objective(
                    id="wazuh-obj",
                    description="Detect alerts",
                    type=ObjectiveType.WAZUH_ALERT,
                    points=75,
                    wazuh_alert=WazuhAlertValidation(
                        query={"match_all": {}},
                        min_matches=1,
                    ),
                ),
            ],
        ),
        scoring=ScoringConfig(passing_score=100, max_score=225),
    )


@pytest.fixture
def session_mgr(tmp_path: Path) -> ScenarioSession:
    return ScenarioSession(tmp_path / ".aptl")


@pytest.fixture
def active_session(
    session_mgr: ScenarioSession, scenario_with_evaluable: ScenarioDefinition
):
    return session_mgr.start(scenario_with_evaluable)


def _mock_otel(mocker):
    """Mock all OTel calls used by the engine."""
    mocker.patch("aptl.core.engine.init_tracing")
    mocker.patch("aptl.core.engine.shutdown_tracing")
    mocker.patch("aptl.core.engine.get_tracer", return_value=MagicMock())
    mocker.patch("aptl.core.engine.make_parent_context", return_value=MagicMock())
    mock_span = MagicMock()
    mocker.patch("aptl.core.engine.create_child_span", return_value=mock_span)
    return mock_span


# ---------------------------------------------------------------------------
# evaluate_once tests
# ---------------------------------------------------------------------------


def test_evaluate_once_records_completions(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """evaluate_once records newly-passed objectives in session."""
    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Mocked pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)

    engine = ScenarioEngine(scenario_with_evaluable, session_mgr)
    results = asyncio.run(engine.evaluate_once())

    # Should evaluate cmd-obj and wazuh-obj (not manual-obj)
    assert len(results) == 2
    assert all(r.passed for r in results)

    session = session_mgr.get_active()
    assert "cmd-obj" in session.completed_objectives
    assert "wazuh-obj" in session.completed_objectives
    assert "manual-obj" not in session.completed_objectives


def test_evaluate_once_skips_completed(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """evaluate_once skips already-completed objectives."""
    session_mgr.record_objective_complete("cmd-obj")

    call_count = 0

    async def mock_evaluate(obj, started_at):
        nonlocal call_count
        call_count += 1
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Mocked pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)

    engine = ScenarioEngine(scenario_with_evaluable, session_mgr)
    results = asyncio.run(engine.evaluate_once())

    assert call_count == 1
    assert len(results) == 1
    assert results[0].objective_id == "wazuh-obj"


def test_evaluate_once_no_pending(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """evaluate_once returns empty when all evaluable objectives are done."""
    session_mgr.record_objective_complete("cmd-obj")
    session_mgr.record_objective_complete("wazuh-obj")

    engine = ScenarioEngine(scenario_with_evaluable, session_mgr)
    results = asyncio.run(engine.evaluate_once())
    assert results == []


# ---------------------------------------------------------------------------
# run loop tests
# ---------------------------------------------------------------------------


def test_run_exits_when_all_complete(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine loop exits when all evaluable objectives are complete."""
    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Mocked pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)
    _mock_otel(mocker)

    engine = ScenarioEngine(
        scenario_with_evaluable, session_mgr, poll_interval=0.1
    )

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    result = asyncio.run(drive())

    assert result.evaluation_cycles >= 1
    assert "cmd-obj" in result.completed_objectives
    assert "wazuh-obj" in result.completed_objectives
    assert result.score is not None
    assert not result.timed_out


def test_run_exits_on_shutdown(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine loop exits when shutdown event is set."""
    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=False,
            detail="Not yet",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)
    _mock_otel(mocker)

    engine = ScenarioEngine(
        scenario_with_evaluable, session_mgr, poll_interval=0.1
    )

    async def drive():
        shutdown = asyncio.Event()

        async def signal_shutdown():
            await asyncio.sleep(0.15)
            shutdown.set()

        asyncio.create_task(signal_shutdown())
        return await engine.run(shutdown)

    result = asyncio.run(drive())

    assert result.evaluation_cycles >= 1
    assert not result.timed_out


def test_run_exits_on_timeout(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine loop exits when timeout is reached."""
    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=False,
            detail="Not yet",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)
    _mock_otel(mocker)

    engine = ScenarioEngine(
        scenario_with_evaluable,
        session_mgr,
        poll_interval=0.05,
        timeout_minutes=0.001,  # ~0.06 seconds
    )

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    result = asyncio.run(drive())
    assert result.timed_out is True


# ---------------------------------------------------------------------------
# get_score tests
# ---------------------------------------------------------------------------


def test_get_score(session_mgr, active_session, scenario_with_evaluable):
    """get_score returns current score snapshot."""
    session_mgr.record_objective_complete("cmd-obj")

    engine = ScenarioEngine(scenario_with_evaluable, session_mgr)
    score = engine.get_score()

    assert score is not None
    assert score.total_score == 100  # cmd-obj is 100 pts
    assert score.passed is True  # passing_score is 100


# ---------------------------------------------------------------------------
# OTel span emission
# ---------------------------------------------------------------------------


def test_run_emits_otel_spans(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine emits OTel evaluation spans for each objective checked."""
    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)
    mock_span = _mock_otel(mocker)
    create_span = mocker.patch(
        "aptl.core.engine.create_child_span", return_value=mock_span
    )

    engine = ScenarioEngine(
        scenario_with_evaluable, session_mgr, poll_interval=0.1
    )

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    asyncio.run(drive())

    assert create_span.call_count >= 2
    mock_span.end.assert_called()


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------


def test_run_invokes_progress_callback(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine invokes the progress callback after each cycle."""
    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)
    _mock_otel(mocker)

    progress_calls = []

    def on_progress(cycle, results, score):
        progress_calls.append((cycle, len(results), score.total_score))

    engine = ScenarioEngine(
        scenario_with_evaluable,
        session_mgr,
        poll_interval=0.1,
        on_progress=on_progress,
    )

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    asyncio.run(drive())

    assert len(progress_calls) >= 1
    assert progress_calls[0][0] == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_run_no_active_session(session_mgr, scenario_with_evaluable, mocker):
    """Engine returns empty result when no session is active."""
    _mock_otel(mocker)

    engine = ScenarioEngine(scenario_with_evaluable, session_mgr)

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    result = asyncio.run(drive())
    assert result.completed_objectives == []
    assert result.evaluation_cycles == 0


def test_run_session_disappears_mid_loop(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine exits gracefully if session file is deleted during run."""
    call_count = 0
    original_get_active = session_mgr.get_active

    def get_active_then_none():
        nonlocal call_count
        call_count += 1
        # First call succeeds (initial check), second returns None (mid-loop)
        if call_count <= 1:
            return original_get_active()
        return None

    mocker.patch.object(session_mgr, "get_active", side_effect=get_active_then_none)
    _mock_otel(mocker)

    engine = ScenarioEngine(
        scenario_with_evaluable, session_mgr, poll_interval=0.1
    )

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    result = asyncio.run(drive())
    assert result.evaluation_cycles >= 1


def test_run_progress_callback_error_does_not_crash(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine continues if progress callback raises."""
    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)
    _mock_otel(mocker)

    def bad_callback(cycle, results, score):
        raise RuntimeError("callback crashed")

    engine = ScenarioEngine(
        scenario_with_evaluable,
        session_mgr,
        poll_interval=0.1,
        on_progress=bad_callback,
    )

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    result = asyncio.run(drive())
    # Engine should complete despite callback error
    assert result.evaluation_cycles >= 1
    assert "cmd-obj" in result.completed_objectives


def test_evaluate_once_handles_evaluator_exception(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """evaluate_once logs and skips objectives that raise exceptions."""
    call_count = 0

    async def mock_evaluate(obj, started_at):
        nonlocal call_count
        call_count += 1
        if obj.id == "cmd-obj":
            raise RuntimeError("evaluator exploded")
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)

    engine = ScenarioEngine(scenario_with_evaluable, session_mgr)
    results = asyncio.run(engine.evaluate_once())

    # cmd-obj raised, wazuh-obj succeeded
    assert len(results) == 1
    assert results[0].objective_id == "wazuh-obj"


def test_get_score_no_session(session_mgr, scenario_with_evaluable):
    """get_score returns None when no session is active."""
    engine = ScenarioEngine(scenario_with_evaluable, session_mgr)
    assert engine.get_score() is None


def test_run_state_transition_errors_are_handled(
    mocker, session_mgr, active_session, scenario_with_evaluable
):
    """Engine handles ScenarioStateError from set_evaluating/set_active gracefully."""
    from aptl.core.scenarios import ScenarioStateError

    async def mock_evaluate(obj, started_at):
        return EvaluationResult(
            objective_id=obj.id,
            passed=True,
            detail="Pass",
            checked_at="2026-03-26T10:01:00+00:00",
        )

    mocker.patch("aptl.core.engine.evaluate_objective", side_effect=mock_evaluate)
    _mock_otel(mocker)

    # Make state transitions fail
    mocker.patch.object(
        session_mgr, "set_evaluating",
        side_effect=ScenarioStateError("already evaluating"),
    )
    mocker.patch.object(
        session_mgr, "set_active_from_evaluating",
        side_effect=ScenarioStateError("not in evaluating"),
    )

    engine = ScenarioEngine(
        scenario_with_evaluable, session_mgr, poll_interval=0.1
    )

    async def drive():
        shutdown = asyncio.Event()
        return await engine.run(shutdown)

    result = asyncio.run(drive())
    # Engine should complete despite state transition errors
    assert result.evaluation_cycles >= 1
    assert "cmd-obj" in result.completed_objectives
