"""Scenario session state management.

Tracks the active scenario session across CLI invocations via a JSON
file in the .aptl/ state directory. Enforces valid state transitions
and provides methods to record hints, objective completions, and
session lifecycle events.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from aptl.core.scenarios import ScenarioDefinition, ScenarioStateError
from aptl.utils.logging import get_logger

log = get_logger("session")

_SESSION_FILENAME = "session.json"


class SessionState(str, Enum):
    """Lifecycle state of a scenario session."""

    IDLE = "idle"
    ACTIVE = "active"
    EVALUATING = "evaluating"
    COMPLETED = "completed"


@dataclass
class ActiveSession:
    """Persistent state for a running scenario.

    Attributes:
        scenario_id: ID of the active scenario.
        state: Current lifecycle state.
        started_at: ISO 8601 UTC timestamp of when the session started.
        trace_id: Hex trace ID for OpenTelemetry distributed tracing.
        hints_used: Map of objective_id to highest hint level revealed.
        completed_objectives: List of objective IDs that have been completed.
        flags: CTF flags captured at scenario start, keyed by container name.
    """

    scenario_id: str
    state: SessionState
    started_at: str
    trace_id: str = ""
    hints_used: dict[str, int] = field(default_factory=dict)
    completed_objectives: list[str] = field(default_factory=list)
    flags: dict[str, dict[str, dict]] = field(default_factory=dict)
    run_id: str = ""


def _serialize_session(session: ActiveSession) -> dict:
    """Convert an ActiveSession to a JSON-serializable dict.

    Args:
        session: The session to serialize.

    Returns:
        A plain dict suitable for json.dumps().
    """
    d = asdict(session)
    d["state"] = session.state.value
    return d


def _deserialize_session(data: dict) -> ActiveSession:
    """Restore an ActiveSession from a deserialized dict.

    Args:
        data: A dict loaded from session.json.

    Returns:
        The restored ActiveSession.

    Raises:
        ValueError: If the data is malformed or missing required fields.
    """
    try:
        return ActiveSession(
            scenario_id=data["scenario_id"],
            state=SessionState(data["state"]),
            started_at=data["started_at"],
            trace_id=data.get("trace_id", ""),
            hints_used=data.get("hints_used", {}),
            completed_objectives=data.get("completed_objectives", []),
            flags=data.get("flags", {}),
            run_id=data.get("run_id", ""),
        )
    except (KeyError, ValueError) as e:
        raise ValueError(f"Malformed session data: {e}") from e


class ScenarioSession:
    """Manages active scenario state across CLI invocations.

    State is persisted to a JSON file in the .aptl/ directory so that
    separate CLI commands (start, status, evaluate, stop) share context.
    """

    def __init__(self, state_dir: Path) -> None:
        """Initialize session manager.

        Args:
            state_dir: Path to the .aptl/ directory. Created on first
                write if it does not exist.
        """
        self._state_dir = state_dir
        self._session_path = state_dir / _SESSION_FILENAME
        log.debug("Session manager initialized at %s", state_dir)

    @property
    def session_path(self) -> Path:
        """Path to the session.json file."""
        return self._session_path

    @property
    def state_dir(self) -> Path:
        """Path to the .aptl/ state directory."""
        return self._state_dir

    def is_active(self) -> bool:
        """Check if a scenario is currently active.

        Returns:
            True if a session file exists and the state is ACTIVE
            or EVALUATING.
        """
        session = self.get_active()
        if session is None:
            return False
        return session.state in (SessionState.ACTIVE, SessionState.EVALUATING)

    def get_active(self) -> Optional[ActiveSession]:
        """Load the current session from disk.

        Returns:
            The current session, or None if no session file exists.

        Raises:
            ScenarioStateError: If the session file exists but is corrupt.
        """
        if not self._session_path.exists():
            return None

        raw = self._session_path.read_text().strip()
        if not raw:
            return None

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ScenarioStateError(
                f"Corrupt session file {self._session_path}: {e}"
            ) from e

        try:
            session = _deserialize_session(data)
        except ValueError as e:
            raise ScenarioStateError(str(e)) from e

        log.debug(
            "Loaded session: scenario='%s', state=%s",
            session.scenario_id,
            session.state.value,
        )
        return session

    def start(
        self,
        scenario: ScenarioDefinition,
    ) -> ActiveSession:
        """Start a new scenario session.

        Creates the session file and returns the new session.
        Generates a trace_id for OpenTelemetry distributed tracing.

        Args:
            scenario: The scenario being started.

        Returns:
            The newly created ActiveSession.

        Raises:
            ScenarioStateError: If a scenario is already active.
        """
        if self.is_active():
            existing = self.get_active()
            raise ScenarioStateError(
                f"Cannot start scenario '{scenario.metadata.id}': "
                f"scenario '{existing.scenario_id}' is already active. "
                "Stop it first with 'aptl scenario stop'."
            )

        from aptl.core.telemetry import generate_trace_context

        ctx = generate_trace_context()

        session = ActiveSession(
            scenario_id=scenario.metadata.id,
            state=SessionState.ACTIVE,
            started_at=datetime.now(timezone.utc).isoformat(),
            trace_id=ctx["trace_id"],
        )

        self._write(session)
        log.info("Started session for scenario '%s'", scenario.metadata.id)
        return session

    def record_hint(self, objective_id: str, hint_level: int) -> None:
        """Record that a hint was used for an objective.

        Only updates if the new level is higher than any previously
        recorded level for this objective.

        Args:
            objective_id: The objective the hint is for.
            hint_level: The hint level revealed.

        Raises:
            ScenarioStateError: If no scenario is active.
        """
        session = self._require_active()
        current_level = session.hints_used.get(objective_id, 0)
        if hint_level > current_level:
            session.hints_used[objective_id] = hint_level
            self._write(session)
            log.info(
                "Recorded hint level %d for objective '%s'",
                hint_level,
                objective_id,
            )
        else:
            log.debug(
                "Hint level %d for '%s' not recorded (current: %d)",
                hint_level,
                objective_id,
                current_level,
            )

    def record_objective_complete(self, objective_id: str) -> None:
        """Record that an objective was completed.

        Idempotent: recording the same objective twice is a no-op.

        Args:
            objective_id: The completed objective.

        Raises:
            ScenarioStateError: If no scenario is active.
        """
        session = self._require_active()
        if objective_id not in session.completed_objectives:
            session.completed_objectives.append(objective_id)
            self._write(session)
            log.info("Recorded objective '%s' as complete", objective_id)
        else:
            log.debug("Objective '%s' already recorded as complete", objective_id)

    def finish(self) -> ActiveSession:
        """Mark the current session as completed and return it.

        Returns:
            The completed session with final state.

        Raises:
            ScenarioStateError: If no scenario is active.
        """
        session = self._require_active()
        session.state = SessionState.COMPLETED
        self._write(session)
        log.info("Finished session for scenario '%s'", session.scenario_id)
        return session

    def clear(self) -> None:
        """Remove the session file.

        Used after report generation to return to idle state. Safe to
        call when no session exists (no-op).
        """
        if self._session_path.exists():
            self._session_path.unlink()
            log.info("Cleared session file")
        else:
            log.debug("No session file to clear")

    def _require_active(self) -> ActiveSession:
        """Load the current session and verify it is active.

        Returns:
            The active session.

        Raises:
            ScenarioStateError: If no session is active.
        """
        session = self.get_active()
        if session is None:
            raise ScenarioStateError(
                "No active scenario. Start one with 'aptl scenario start'."
            )
        if session.state not in (SessionState.ACTIVE, SessionState.EVALUATING):
            raise ScenarioStateError(
                f"Scenario '{session.scenario_id}' is in state "
                f"'{session.state.value}', not active."
            )
        return session

    def _write(self, session: ActiveSession) -> None:
        """Persist session state to disk.

        Creates the state directory and parent directories if needed.

        Args:
            session: The session to persist.
        """
        self._state_dir.mkdir(parents=True, exist_ok=True)
        data = _serialize_session(session)
        self._session_path.write_text(
            json.dumps(data, indent=2) + "\n",
            encoding="utf-8",
        )
        log.debug("Wrote session to %s", self._session_path)
