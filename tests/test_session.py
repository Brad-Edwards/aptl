"""Tests for scenario session state management.

Tests exercise session lifecycle (start/finish/clear), state persistence
across reads, hint and objective recording, state transition enforcement,
and error handling for corrupt files.
"""

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scenario_def(scenario_id: str = "test-scenario"):
    """Create a minimal ScenarioDefinition for testing."""
    from aptl.core.scenarios import ScenarioDefinition

    return ScenarioDefinition(
        metadata={
            "id": scenario_id,
            "name": "Test Scenario",
            "description": "A test scenario",
            "difficulty": "beginner",
            "estimated_minutes": 10,
        },
        mode="red",
        containers={"required": ["kali"]},
        objectives={
            "red": [
                {"id": "obj-a", "description": "Do A", "type": "manual", "points": 50},
                {"id": "obj-b", "description": "Do B", "type": "manual", "points": 50},
            ],
            "blue": [],
        },
    )


# ---------------------------------------------------------------------------
# SessionState enum
# ---------------------------------------------------------------------------


class TestSessionState:
    """Tests for the SessionState enum."""

    def test_all_states(self):
        """All expected session states should be defined."""
        from aptl.core.session import SessionState

        assert SessionState.IDLE == "idle"
        assert SessionState.ACTIVE == "active"
        assert SessionState.EVALUATING == "evaluating"
        assert SessionState.COMPLETED == "completed"


# ---------------------------------------------------------------------------
# ActiveSession dataclass
# ---------------------------------------------------------------------------


class TestActiveSession:
    """Tests for the ActiveSession dataclass."""

    def test_creation_with_defaults(self):
        """ActiveSession should have empty defaults for optional fields."""
        from aptl.core.session import ActiveSession, SessionState

        session = ActiveSession(
            scenario_id="test",
            state=SessionState.ACTIVE,
            started_at="2026-02-16T14:30:00+00:00",
        )
        assert session.hints_used == {}
        assert session.completed_objectives == []
        assert session.trace_id == ""

    def test_creation_with_all_fields(self):
        """ActiveSession should accept all fields."""
        from aptl.core.session import ActiveSession, SessionState

        session = ActiveSession(
            scenario_id="test",
            state=SessionState.ACTIVE,
            started_at="2026-02-16T14:30:00+00:00",
            trace_id="a" * 32,
            hints_used={"obj-a": 2},
            completed_objectives=["obj-a"],
        )
        assert session.hints_used == {"obj-a": 2}
        assert session.completed_objectives == ["obj-a"]
        assert session.trace_id == "a" * 32


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestSessionSerialization:
    """Tests for session serialization and deserialization."""

    def test_round_trip(self):
        """An ActiveSession should survive serialize -> deserialize."""
        from aptl.core.session import (
            ActiveSession,
            SessionState,
            _deserialize_session,
            _serialize_session,
        )

        original = ActiveSession(
            scenario_id="test-scenario",
            state=SessionState.ACTIVE,
            started_at="2026-02-16T14:30:00+00:00",
            trace_id="a" * 32,
            hints_used={"obj-a": 1},
            completed_objectives=["obj-b"],
        )
        data = _serialize_session(original)
        restored = _deserialize_session(data)

        assert restored.scenario_id == original.scenario_id
        assert restored.state == original.state
        assert restored.started_at == original.started_at
        assert restored.trace_id == original.trace_id
        assert restored.hints_used == original.hints_used
        assert restored.completed_objectives == original.completed_objectives

    def test_serialize_state_as_string(self):
        """Serialized state should be a string value, not an enum."""
        from aptl.core.session import ActiveSession, SessionState, _serialize_session

        session = ActiveSession(
            scenario_id="test",
            state=SessionState.ACTIVE,
            started_at="2026-02-16T14:30:00+00:00",
        )
        data = _serialize_session(session)
        assert data["state"] == "active"
        assert isinstance(data["state"], str)

    def test_deserialize_missing_field_raises(self):
        """Deserializing data with missing required fields should raise."""
        from aptl.core.session import _deserialize_session

        with pytest.raises(ValueError, match="Malformed"):
            _deserialize_session({"scenario_id": "test"})

    def test_deserialize_invalid_state_raises(self):
        """Deserializing an unknown state value should raise."""
        from aptl.core.session import _deserialize_session

        with pytest.raises(ValueError, match="Malformed"):
            _deserialize_session({
                "scenario_id": "test",
                "state": "unknown_state",
                "started_at": "2026-02-16T14:30:00+00:00",
            })

    def test_deserialize_defaults_optional_fields(self):
        """Deserialization should default trace_id, hints_used and completed_objectives."""
        from aptl.core.session import _deserialize_session

        session = _deserialize_session({
            "scenario_id": "test",
            "state": "active",
            "started_at": "2026-02-16T14:30:00+00:00",
        })
        assert session.trace_id == ""
        assert session.hints_used == {}
        assert session.completed_objectives == []


# ---------------------------------------------------------------------------
# ScenarioSession - start
# ---------------------------------------------------------------------------


class TestScenarioSessionStart:
    """Tests for starting a scenario session."""

    def test_start_creates_session_file(self, aptl_state_dir):
        """Starting a session should create session.json."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        scenario = _make_scenario_def()

        session = mgr.start(scenario)

        assert mgr.session_path.exists()
        assert session.scenario_id == "test-scenario"
        assert session.state.value == "active"

    def test_start_writes_valid_json(self, aptl_state_dir):
        """Session file should contain valid JSON."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        data = json.loads(mgr.session_path.read_text())
        assert data["scenario_id"] == "test-scenario"
        assert data["state"] == "active"

    def test_start_creates_state_dir_if_missing(self, tmp_path):
        """Starting should create the .aptl/ directory if needed."""
        from aptl.core.session import ScenarioSession

        state_dir = tmp_path / "new_aptl_dir"
        mgr = ScenarioSession(state_dir)
        mgr.start(_make_scenario_def())

        assert state_dir.exists()
        assert mgr.session_path.exists()

    def test_start_rejects_when_already_active(self, aptl_state_dir):
        """Starting when a session is already active should raise."""
        from aptl.core.scenarios import ScenarioStateError
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def("first"))

        with pytest.raises(ScenarioStateError, match="already active"):
            mgr.start(_make_scenario_def("second"))

    def test_start_sets_utc_timestamp(self, aptl_state_dir):
        """Session started_at should be a UTC ISO 8601 timestamp."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        session = mgr.start(_make_scenario_def())
        assert "T" in session.started_at
        assert "+" in session.started_at or "Z" in session.started_at

    def test_start_generates_trace_id(self, aptl_state_dir):
        """Starting a session should generate a 32-char hex trace_id."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        session = mgr.start(_make_scenario_def())
        assert len(session.trace_id) == 32
        int(session.trace_id, 16)  # should not raise


# ---------------------------------------------------------------------------
# ScenarioSession - get_active / is_active
# ---------------------------------------------------------------------------


class TestScenarioSessionGetActive:
    """Tests for reading active session state."""

    def test_get_active_returns_none_when_no_session(self, aptl_state_dir):
        """get_active should return None when no session file exists."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        assert mgr.get_active() is None

    def test_get_active_returns_session(self, aptl_state_dir):
        """get_active should return the persisted session."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        session = mgr.get_active()
        assert session is not None
        assert session.scenario_id == "test-scenario"

    def test_is_active_true_when_active(self, aptl_state_dir):
        """is_active should return True when a session is active."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())
        assert mgr.is_active() is True

    def test_is_active_false_when_no_session(self, aptl_state_dir):
        """is_active should return False when no session exists."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        assert mgr.is_active() is False

    def test_is_active_false_when_completed(self, aptl_state_dir):
        """is_active should return False when session is completed."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())
        mgr.finish()
        assert mgr.is_active() is False

    def test_get_active_corrupt_json_raises(self, aptl_state_dir):
        """get_active should raise ScenarioStateError for corrupt JSON."""
        from aptl.core.scenarios import ScenarioStateError
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.session_path.write_text("{not valid json!!!")

        with pytest.raises(ScenarioStateError, match="[Cc]orrupt"):
            mgr.get_active()

    def test_get_active_empty_file_returns_none(self, aptl_state_dir):
        """get_active should return None for an empty session file."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.session_path.write_text("")
        assert mgr.get_active() is None

    def test_persistence_across_instances(self, aptl_state_dir):
        """State should persist across different ScenarioSession instances."""
        from aptl.core.session import ScenarioSession

        mgr1 = ScenarioSession(aptl_state_dir)
        mgr1.start(_make_scenario_def())

        mgr2 = ScenarioSession(aptl_state_dir)
        session = mgr2.get_active()
        assert session is not None
        assert session.scenario_id == "test-scenario"


# ---------------------------------------------------------------------------
# ScenarioSession - record_hint
# ---------------------------------------------------------------------------


class TestScenarioSessionRecordHint:
    """Tests for recording hint usage."""

    def test_record_hint(self, aptl_state_dir):
        """Recording a hint should persist it to disk."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        mgr.record_hint("obj-a", 1)

        session = mgr.get_active()
        assert session.hints_used == {"obj-a": 1}

    def test_record_higher_hint_level_updates(self, aptl_state_dir):
        """Recording a higher hint level should update the stored level."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        mgr.record_hint("obj-a", 1)
        mgr.record_hint("obj-a", 2)

        session = mgr.get_active()
        assert session.hints_used["obj-a"] == 2

    def test_record_lower_hint_level_is_noop(self, aptl_state_dir):
        """Recording a lower hint level should not overwrite."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        mgr.record_hint("obj-a", 2)
        mgr.record_hint("obj-a", 1)

        session = mgr.get_active()
        assert session.hints_used["obj-a"] == 2

    def test_record_hint_no_active_session_raises(self, aptl_state_dir):
        """Recording a hint with no active session should raise."""
        from aptl.core.scenarios import ScenarioStateError
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        with pytest.raises(ScenarioStateError, match="No active"):
            mgr.record_hint("obj-a", 1)

    def test_record_hints_for_multiple_objectives(self, aptl_state_dir):
        """Hints for different objectives should be tracked independently."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        mgr.record_hint("obj-a", 1)
        mgr.record_hint("obj-b", 2)

        session = mgr.get_active()
        assert session.hints_used == {"obj-a": 1, "obj-b": 2}


# ---------------------------------------------------------------------------
# ScenarioSession - record_objective_complete
# ---------------------------------------------------------------------------


class TestScenarioSessionRecordObjective:
    """Tests for recording objective completions."""

    def test_record_objective_complete(self, aptl_state_dir):
        """Recording a completed objective should persist it."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        mgr.record_objective_complete("obj-a")

        session = mgr.get_active()
        assert "obj-a" in session.completed_objectives

    def test_record_same_objective_is_idempotent(self, aptl_state_dir):
        """Recording the same objective twice should not duplicate it."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        mgr.record_objective_complete("obj-a")
        mgr.record_objective_complete("obj-a")

        session = mgr.get_active()
        assert session.completed_objectives.count("obj-a") == 1

    def test_record_multiple_objectives(self, aptl_state_dir):
        """Multiple distinct objectives should all be recorded."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        mgr.record_objective_complete("obj-a")
        mgr.record_objective_complete("obj-b")

        session = mgr.get_active()
        assert set(session.completed_objectives) == {"obj-a", "obj-b"}

    def test_record_objective_no_active_session_raises(self, aptl_state_dir):
        """Recording an objective with no active session should raise."""
        from aptl.core.scenarios import ScenarioStateError
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        with pytest.raises(ScenarioStateError, match="No active"):
            mgr.record_objective_complete("obj-a")


# ---------------------------------------------------------------------------
# ScenarioSession - finish
# ---------------------------------------------------------------------------


class TestScenarioSessionFinish:
    """Tests for finishing a scenario session."""

    def test_finish_sets_completed_state(self, aptl_state_dir):
        """finish should transition state to COMPLETED."""
        from aptl.core.session import ScenarioSession, SessionState

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())

        finished = mgr.finish()
        assert finished.state == SessionState.COMPLETED

    def test_finish_persists_to_disk(self, aptl_state_dir):
        """Finished state should be persisted."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())
        mgr.finish()

        data = json.loads(mgr.session_path.read_text())
        assert data["state"] == "completed"

    def test_finish_no_active_session_raises(self, aptl_state_dir):
        """finish with no active session should raise."""
        from aptl.core.scenarios import ScenarioStateError
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        with pytest.raises(ScenarioStateError, match="No active"):
            mgr.finish()

    def test_finish_returns_session_with_accumulated_state(self, aptl_state_dir):
        """finish should return the session with all recorded state."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())
        mgr.record_hint("obj-a", 1)
        mgr.record_objective_complete("obj-b")

        finished = mgr.finish()
        assert finished.hints_used == {"obj-a": 1}
        assert finished.completed_objectives == ["obj-b"]


# ---------------------------------------------------------------------------
# ScenarioSession - clear
# ---------------------------------------------------------------------------


class TestScenarioSessionClear:
    """Tests for clearing the session file."""

    def test_clear_removes_session_file(self, aptl_state_dir):
        """clear should delete the session.json file."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def())
        assert mgr.session_path.exists()

        mgr.clear()
        assert not mgr.session_path.exists()

    def test_clear_is_safe_when_no_session(self, aptl_state_dir):
        """clear should not raise when no session file exists."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.clear()  # Should not raise

    def test_clear_allows_new_start(self, aptl_state_dir):
        """After clear, starting a new scenario should succeed."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        mgr.start(_make_scenario_def("first"))
        mgr.finish()
        mgr.clear()

        session = mgr.start(_make_scenario_def("second"))
        assert session.scenario_id == "second"


# ---------------------------------------------------------------------------
# ScenarioSession - properties
# ---------------------------------------------------------------------------


class TestScenarioSessionProperties:
    """Tests for ScenarioSession properties."""

    def test_session_path(self, aptl_state_dir):
        """session_path should point to session.json in state dir."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        assert mgr.session_path == aptl_state_dir / "session.json"

    def test_state_dir(self, aptl_state_dir):
        """state_dir should return the configured directory."""
        from aptl.core.session import ScenarioSession

        mgr = ScenarioSession(aptl_state_dir)
        assert mgr.state_dir == aptl_state_dir
