"""Tests for the event timeline system.

Tests exercise event creation, JSONL serialization/deserialization,
append/read operations, query filtering, and error handling for
corrupted or missing log files.
"""

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Event and EventType
# ---------------------------------------------------------------------------


class TestEventType:
    """Tests for the EventType enum."""

    def test_all_event_types_exist(self):
        """All expected event types should be defined."""
        from aptl.core.events import EventType

        expected = {
            "scenario_started",
            "scenario_stopped",
            "precondition_applied",
            "precondition_failed",
            "objective_completed",
            "objective_failed",
            "alert_matched",
            "hint_requested",
            "evaluation_run",
        }
        actual = {e.value for e in EventType}
        assert actual == expected

    def test_event_type_is_string(self):
        """EventType values should be usable as strings."""
        from aptl.core.events import EventType

        assert EventType.SCENARIO_STARTED == "scenario_started"


class TestEvent:
    """Tests for the Event dataclass."""

    def test_event_creation(self):
        """An event with all fields should be valid."""
        from aptl.core.events import Event, EventType

        event = Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test-scenario",
            timestamp="2026-02-16T14:30:00+00:00",
            data={"mode": "red"},
        )
        assert event.event_type == EventType.SCENARIO_STARTED
        assert event.scenario_id == "test-scenario"
        assert event.data == {"mode": "red"}

    def test_event_default_data(self):
        """Event data should default to an empty dict."""
        from aptl.core.events import Event, EventType

        event = Event(
            event_type=EventType.SCENARIO_STOPPED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        )
        assert event.data == {}


class TestMakeEvent:
    """Tests for the make_event helper."""

    def test_creates_event_with_utc_timestamp(self):
        """make_event should produce an event with a UTC ISO 8601 timestamp."""
        from aptl.core.events import EventType, make_event

        event = make_event(EventType.SCENARIO_STARTED, "test-scenario")
        assert event.event_type == EventType.SCENARIO_STARTED
        assert event.scenario_id == "test-scenario"
        assert "T" in event.timestamp
        assert "+" in event.timestamp or "Z" in event.timestamp

    def test_creates_event_with_data(self):
        """make_event should include the provided data dict."""
        from aptl.core.events import EventType, make_event

        event = make_event(
            EventType.HINT_REQUESTED,
            "test",
            data={"objective_id": "obj-1", "level": 2},
        )
        assert event.data == {"objective_id": "obj-1", "level": 2}

    def test_creates_event_with_empty_data_by_default(self):
        """make_event with no data arg should default to empty dict."""
        from aptl.core.events import EventType, make_event

        event = make_event(EventType.EVALUATION_RUN, "test")
        assert event.data == {}


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for event serialization and deserialization."""

    def test_round_trip(self):
        """An event should survive serialize -> deserialize."""
        from aptl.core.events import Event, EventType, _deserialize_event, _serialize_event

        original = Event(
            event_type=EventType.OBJECTIVE_COMPLETED,
            scenario_id="test-scenario",
            timestamp="2026-02-16T14:30:00+00:00",
            data={"objective_id": "find-flag", "points": 100},
        )
        serialized = _serialize_event(original)
        restored = _deserialize_event(serialized)
        assert restored.event_type == original.event_type
        assert restored.scenario_id == original.scenario_id
        assert restored.timestamp == original.timestamp
        assert restored.data == original.data

    def test_serialize_produces_valid_json(self):
        """Serialization should produce parseable JSON."""
        from aptl.core.events import Event, EventType, _serialize_event

        event = Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        )
        serialized = _serialize_event(event)
        parsed = json.loads(serialized)
        assert parsed["event_type"] == "scenario_started"
        assert parsed["scenario_id"] == "test"

    def test_serialize_is_compact(self):
        """Serialized events should not contain unnecessary whitespace."""
        from aptl.core.events import Event, EventType, _serialize_event

        event = Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        )
        serialized = _serialize_event(event)
        assert "  " not in serialized
        assert ": " not in serialized

    def test_deserialize_invalid_json_raises(self):
        """Deserializing invalid JSON should raise ValueError."""
        from aptl.core.events import _deserialize_event

        with pytest.raises(ValueError, match="Invalid JSON"):
            _deserialize_event("{not valid json}")

    def test_deserialize_missing_fields_raises(self):
        """Deserializing JSON with missing required fields should raise."""
        from aptl.core.events import _deserialize_event

        with pytest.raises(ValueError, match="Malformed"):
            _deserialize_event('{"event_type":"scenario_started"}')

    def test_deserialize_invalid_event_type_raises(self):
        """Deserializing an unknown event type should raise ValueError."""
        from aptl.core.events import _deserialize_event

        line = json.dumps({
            "event_type": "unknown_type",
            "scenario_id": "test",
            "timestamp": "2026-02-16T14:30:00+00:00",
        })
        with pytest.raises(ValueError, match="Malformed"):
            _deserialize_event(line)


# ---------------------------------------------------------------------------
# EventLog append and read
# ---------------------------------------------------------------------------


class TestEventLogAppend:
    """Tests for EventLog.append()."""

    def test_append_creates_file(self, tmp_path):
        """Appending to a new log should create the file."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "events" / "test.jsonl"
        event_log = EventLog(log_path)
        event = Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        )
        event_log.append(event)
        assert log_path.exists()

    def test_append_creates_parent_directories(self, tmp_path):
        """Appending should create parent directories if needed."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "deep" / "nested" / "events.jsonl"
        event_log = EventLog(log_path)
        event = Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        )
        event_log.append(event)
        assert log_path.exists()

    def test_append_writes_one_line_per_event(self, tmp_path):
        """Each append should add exactly one line."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        event_log = EventLog(log_path)

        for i in range(3):
            event_log.append(Event(
                event_type=EventType.EVALUATION_RUN,
                scenario_id="test",
                timestamp=f"2026-02-16T14:3{i}:00+00:00",
            ))

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_append_each_line_is_valid_json(self, tmp_path):
        """Each line in the log should be valid JSON."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        event_log = EventLog(log_path)

        event_log.append(Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
            data={"key": "value"},
        ))

        line = log_path.read_text().strip()
        parsed = json.loads(line)
        assert parsed["event_type"] == "scenario_started"
        assert parsed["data"] == {"key": "value"}


class TestEventLogRead:
    """Tests for EventLog.read_all()."""

    def test_read_all_returns_events_in_order(self, tmp_path):
        """read_all should return events in insertion order."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        event_log = EventLog(log_path)

        types = [
            EventType.SCENARIO_STARTED,
            EventType.PRECONDITION_APPLIED,
            EventType.EVALUATION_RUN,
        ]
        for i, et in enumerate(types):
            event_log.append(Event(
                event_type=et,
                scenario_id="test",
                timestamp=f"2026-02-16T14:3{i}:00+00:00",
            ))

        events = event_log.read_all()
        assert len(events) == 3
        assert events[0].event_type == EventType.SCENARIO_STARTED
        assert events[1].event_type == EventType.PRECONDITION_APPLIED
        assert events[2].event_type == EventType.EVALUATION_RUN

    def test_read_all_nonexistent_file_raises(self, tmp_path):
        """read_all on a nonexistent file should raise FileNotFoundError."""
        from aptl.core.events import EventLog

        event_log = EventLog(tmp_path / "missing.jsonl")
        with pytest.raises(FileNotFoundError):
            event_log.read_all()

    def test_read_all_skips_blank_lines(self, tmp_path):
        """read_all should skip blank lines without error."""
        from aptl.core.events import EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        log_path.write_text(
            '{"event_type":"scenario_started","scenario_id":"test","timestamp":"2026-02-16T14:30:00+00:00","data":{}}\n'
            "\n"
            '{"event_type":"scenario_stopped","scenario_id":"test","timestamp":"2026-02-16T14:31:00+00:00","data":{}}\n'
        )
        event_log = EventLog(log_path)
        events = event_log.read_all()
        assert len(events) == 2

    def test_read_all_skips_malformed_lines(self, tmp_path):
        """read_all should skip malformed lines and continue."""
        from aptl.core.events import EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        log_path.write_text(
            '{"event_type":"scenario_started","scenario_id":"test","timestamp":"2026-02-16T14:30:00+00:00","data":{}}\n'
            "THIS IS NOT JSON\n"
            '{"event_type":"scenario_stopped","scenario_id":"test","timestamp":"2026-02-16T14:31:00+00:00","data":{}}\n'
        )
        event_log = EventLog(log_path)
        events = event_log.read_all()
        assert len(events) == 2
        assert events[0].event_type == EventType.SCENARIO_STARTED
        assert events[1].event_type == EventType.SCENARIO_STOPPED

    def test_read_all_empty_file(self, tmp_path):
        """read_all on an empty file should return an empty list."""
        from aptl.core.events import EventLog

        log_path = tmp_path / "test.jsonl"
        log_path.write_text("")
        event_log = EventLog(log_path)
        events = event_log.read_all()
        assert events == []


# ---------------------------------------------------------------------------
# EventLog queries
# ---------------------------------------------------------------------------


class TestEventLogQueries:
    """Tests for EventLog query methods."""

    def test_query_by_type(self, tmp_path):
        """query_by_type should return only matching events."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        event_log = EventLog(log_path)

        event_log.append(Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        ))
        event_log.append(Event(
            event_type=EventType.HINT_REQUESTED,
            scenario_id="test",
            timestamp="2026-02-16T14:31:00+00:00",
            data={"objective_id": "obj-1"},
        ))
        event_log.append(Event(
            event_type=EventType.HINT_REQUESTED,
            scenario_id="test",
            timestamp="2026-02-16T14:32:00+00:00",
            data={"objective_id": "obj-2"},
        ))

        hints = event_log.query_by_type(EventType.HINT_REQUESTED)
        assert len(hints) == 2
        assert all(e.event_type == EventType.HINT_REQUESTED for e in hints)

    def test_query_by_type_no_matches(self, tmp_path):
        """query_by_type with no matches should return empty list."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        event_log = EventLog(log_path)
        event_log.append(Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        ))

        results = event_log.query_by_type(EventType.OBJECTIVE_COMPLETED)
        assert results == []

    def test_query_by_type_nonexistent_file_raises(self, tmp_path):
        """query_by_type on nonexistent log should raise FileNotFoundError."""
        from aptl.core.events import EventLog, EventType

        event_log = EventLog(tmp_path / "missing.jsonl")
        with pytest.raises(FileNotFoundError):
            event_log.query_by_type(EventType.SCENARIO_STARTED)

    def test_query_by_scenario(self, tmp_path):
        """query_by_scenario should return only matching events."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        event_log = EventLog(log_path)

        event_log.append(Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="scenario-a",
            timestamp="2026-02-16T14:30:00+00:00",
        ))
        event_log.append(Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="scenario-b",
            timestamp="2026-02-16T14:31:00+00:00",
        ))
        event_log.append(Event(
            event_type=EventType.SCENARIO_STOPPED,
            scenario_id="scenario-a",
            timestamp="2026-02-16T14:32:00+00:00",
        ))

        results = event_log.query_by_scenario("scenario-a")
        assert len(results) == 2
        assert all(e.scenario_id == "scenario-a" for e in results)


# ---------------------------------------------------------------------------
# EventLog.is_empty
# ---------------------------------------------------------------------------


class TestEventLogIsEmpty:
    """Tests for EventLog.is_empty()."""

    def test_is_empty_when_file_missing(self, tmp_path):
        """is_empty should return True when the file does not exist."""
        from aptl.core.events import EventLog

        event_log = EventLog(tmp_path / "nonexistent.jsonl")
        assert event_log.is_empty() is True

    def test_is_empty_when_file_empty(self, tmp_path):
        """is_empty should return True when the file has zero bytes."""
        from aptl.core.events import EventLog

        log_path = tmp_path / "empty.jsonl"
        log_path.write_text("")
        event_log = EventLog(log_path)
        assert event_log.is_empty() is True

    def test_is_empty_when_file_has_content(self, tmp_path):
        """is_empty should return False when the file has content."""
        from aptl.core.events import Event, EventLog, EventType

        log_path = tmp_path / "test.jsonl"
        event_log = EventLog(log_path)
        event_log.append(Event(
            event_type=EventType.SCENARIO_STARTED,
            scenario_id="test",
            timestamp="2026-02-16T14:30:00+00:00",
        ))
        assert event_log.is_empty() is False


# ---------------------------------------------------------------------------
# EventLog.path property
# ---------------------------------------------------------------------------


class TestEventLogPath:
    """Tests for EventLog.path property."""

    def test_path_returns_configured_path(self, tmp_path):
        """path property should return the path passed to the constructor."""
        from aptl.core.events import EventLog

        log_path = tmp_path / "events" / "test.jsonl"
        event_log = EventLog(log_path)
        assert event_log.path == log_path
