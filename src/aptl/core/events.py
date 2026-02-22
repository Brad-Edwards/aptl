"""Event timeline for scenario execution.

Provides an append-only event log backed by JSONL (one JSON object per
line). Events are flushed immediately on write for crash safety. The log
supports chronological reads and filtering by event type.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from aptl.utils.logging import get_logger

log = get_logger("events")


class EventType(str, Enum):
    """Types of events that can occur during a scenario."""

    SCENARIO_STARTED = "scenario_started"
    SCENARIO_STOPPED = "scenario_stopped"
    PRECONDITION_APPLIED = "precondition_applied"
    PRECONDITION_FAILED = "precondition_failed"
    OBJECTIVE_COMPLETED = "objective_completed"
    OBJECTIVE_FAILED = "objective_failed"
    ALERT_MATCHED = "alert_matched"
    HINT_REQUESTED = "hint_requested"
    EVALUATION_RUN = "evaluation_run"
    EXPERIMENT_STARTED = "experiment_started"
    EXPERIMENT_SNAPSHOT = "experiment_snapshot"
    EXPERIMENT_COLLECTED = "experiment_collected"
    EXPERIMENT_EXPORTED = "experiment_exported"
    EXPERIMENT_RESET = "experiment_reset"


@dataclass
class Event:
    """A single event in the scenario timeline.

    Attributes:
        event_type: The kind of event.
        scenario_id: ID of the scenario this event belongs to.
        timestamp: ISO 8601 UTC timestamp.
        data: Arbitrary event-specific payload.
    """

    event_type: EventType
    scenario_id: str
    timestamp: str
    data: dict[str, Any] = field(default_factory=dict)


def make_event(
    event_type: EventType,
    scenario_id: str,
    data: Optional[dict[str, Any]] = None,
) -> Event:
    """Create an event with the current UTC timestamp.

    Args:
        event_type: The kind of event.
        scenario_id: ID of the scenario this event belongs to.
        data: Optional event-specific payload.

    Returns:
        A new Event with a UTC ISO 8601 timestamp.
    """
    return Event(
        event_type=event_type,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        data=data or {},
    )


def _serialize_event(event: Event) -> str:
    """Serialize an event to a JSON string.

    Args:
        event: The event to serialize.

    Returns:
        A compact JSON string (no trailing newline).
    """
    d = asdict(event)
    # EventType serializes as its value via asdict, but ensure it's a string
    d["event_type"] = event.event_type.value
    return json.dumps(d, separators=(",", ":"))


def _deserialize_event(line: str) -> Event:
    """Deserialize a JSON string into an Event.

    Args:
        line: A JSON string representing an event.

    Returns:
        The deserialized Event.

    Raises:
        ValueError: If the line is not valid JSON or missing required fields.
    """
    try:
        d = json.loads(line)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in event log: {e}") from e

    try:
        return Event(
            event_type=EventType(d["event_type"]),
            scenario_id=d["scenario_id"],
            timestamp=d["timestamp"],
            data=d.get("data", {}),
        )
    except (KeyError, ValueError) as e:
        raise ValueError(f"Malformed event record: {e}") from e


class EventLog:
    """Append-only event log backed by a JSONL file.

    Each event is written as a single JSON line and flushed immediately.
    Reads are always from disk, ensuring consistency across CLI invocations.
    """

    def __init__(self, path: Path) -> None:
        """Initialize the event log.

        Creates parent directories if needed. The file is created on
        first write, not on initialization.

        Args:
            path: Path to the .jsonl file.
        """
        self._path = path
        log.debug("EventLog initialized at %s", path)

    @property
    def path(self) -> Path:
        """The path to the JSONL file."""
        return self._path

    def append(self, event: Event) -> None:
        """Append an event to the log.

        Writes a single JSON line and flushes immediately for crash
        safety. Creates the file and parent directories on first write.

        Args:
            event: The event to record.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = _serialize_event(event)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
        log.debug(
            "Appended %s event for scenario '%s'",
            event.event_type.value,
            event.scenario_id,
        )

    def read_all(self) -> list[Event]:
        """Read all events from the log file.

        Returns:
            List of Events in chronological order (insertion order).

        Raises:
            FileNotFoundError: If the log file does not exist.
        """
        if not self._path.exists():
            raise FileNotFoundError(f"Event log not found: {self._path}")

        events: list[Event] = []
        for line_num, line in enumerate(
            self._path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                events.append(_deserialize_event(stripped))
            except ValueError as e:
                log.warning(
                    "Skipping malformed event at line %d in %s: %s",
                    line_num,
                    self._path,
                    e,
                )
        return events

    def query_by_type(self, event_type: EventType) -> list[Event]:
        """Filter events by type.

        Args:
            event_type: The type to filter for.

        Returns:
            Matching events in chronological order.

        Raises:
            FileNotFoundError: If the log file does not exist.
        """
        return [e for e in self.read_all() if e.event_type == event_type]

    def query_by_scenario(self, scenario_id: str) -> list[Event]:
        """Filter events by scenario ID.

        Args:
            scenario_id: The scenario ID to filter for.

        Returns:
            Matching events in chronological order.

        Raises:
            FileNotFoundError: If the log file does not exist.
        """
        return [e for e in self.read_all() if e.scenario_id == scenario_id]

    def is_empty(self) -> bool:
        """Check whether the log file exists and has content.

        Returns:
            True if the file does not exist or is empty.
        """
        if not self._path.exists():
            return True
        return self._path.stat().st_size == 0
