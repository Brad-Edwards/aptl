# SOC Feature Specification: Scenario & Observability Core

## 1. Overview

### 1.1 Purpose

The SOC (Scenario & Observability Core) feature adds a scenario engine to APTL
that transforms the existing lab infrastructure into a structured training and
experimentation platform. It provides the ability to define, execute, observe,
evaluate, and score purple team scenarios.

### 1.2 Use Cases

| Use Case | How SOC Enables It |
|---|---|
| **Agentic experimentation** | Define a scenario, point an AI agent at it via MCP, get a structured score. Compare agents, models, prompts by diffing their event logs and scores. |
| **Hybrid purple teaming** | Scenarios with red + blue objectives create coordination structure. Human analyst on blue side, AI agent on red (or vice versa). Scoring tracks both sides. |
| **Skill building / CTF** | Scenarios with difficulty levels, hints, and scoring are CTF challenges. The engine provides the scaffold; individual challenges are YAML data files. |

### 1.3 Design Principles

1. **Match existing patterns exactly** -- Pydantic v2 for validation, dataclasses
   for results, `get_logger()` per module, subprocess for external tools, thin
   CLI over core logic.
2. **Minimal new dependencies** -- Only `PyYAML` is added. Wazuh HTTP queries use
   `urllib.request` from stdlib (matching the subprocess-curl pattern used in
   `services.py` but cleaner for complex JSON bodies).
3. **Scenarios are data, not code** -- YAML files that can be authored, shared,
   and version-controlled independently of the engine.
4. **Incremental delivery** -- Eight phases, each independently testable and
   useful. Phase 1 (schema) is valuable on its own for scenario authoring
   validation.

### 1.4 Non-Goals (v1)

- Multi-tenancy / concurrent scenario execution
- Web UI or real-time dashboards
- Pre-built scenario library (ship 2 examples only)
- Async / event-driven architecture (polling is sufficient for v1)
- MCP server for scenarios (future feature)
- Container provisioning beyond precondition commands

---

## 2. Architecture

### 2.1 Module Map

```
src/aptl/
  core/
    scenarios.py      # Pydantic models, YAML loading, validation
    events.py         # Event types, EventLog, JSONL persistence
    session.py        # Active scenario state, lifecycle transitions
    observer.py       # Wazuh alert queries, objective checking
    objectives.py     # Objective evaluation engine
    scoring.py        # Score calculation, report generation
  cli/
    scenario.py       # Typer command group: list/show/start/status/evaluate/hint/stop

scenarios/                # Scenario definition files (YAML)
  recon-nmap-scan.yaml    # Example: red team reconnaissance
  detect-brute-force.yaml # Example: blue team detection

.aptl/                    # Runtime state directory (gitignored)
  session.json            # Active scenario state
  events/                 # Event timeline logs (JSONL)
  reports/                # After-action reports (JSON)
```

### 2.2 Dependency Graph

```
cli/scenario.py
  -> core/session.py
       -> core/scenarios.py   (models, loading)
       -> core/events.py      (event timeline)
       -> core/observer.py    (Wazuh polling)
       -> core/objectives.py  (evaluation)
       -> core/scoring.py     (score + report)
```

All `core/` modules depend only on:
- `aptl.utils.logging` (existing)
- `aptl.core.config` (existing, for container validation)
- `aptl.core.env` (existing, for Wazuh credentials)
- Python stdlib (`json`, `pathlib`, `datetime`, `enum`, `dataclasses`,
  `threading`, `urllib.request`, `ssl`)
- `pydantic` (existing dependency)
- `yaml` (new dependency: `PyYAML`)

### 2.3 Data Flow

```
                    +-----------------+
                    | scenarios/*.yaml|
                    +--------+--------+
                             |
                     load_scenario()
                             |
                    +--------v--------+
                    | ScenarioDefinition |  (Pydantic, immutable)
                    +--------+--------+
                             |
                   session.start_scenario()
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+          +--------v--------+
     | .aptl/session.json|         | .aptl/events/*.jsonl|
     | (active state)   |         | (append-only log)   |
     +---------+--------+         +---------+-----------+
               |                            |
        evaluate / observe                  |
               |                            |
     +---------v-----------+                |
     | observer.py          |               |
     | (Wazuh alert queries)|               |
     +---------+-----------+                |
               |                            |
     +---------v-----------+                |
     | objectives.py        |               |
     | (check conditions)   +--------->-----+
     +---------+-----------+   (emit events)
               |
     +---------v-----------+
     | scoring.py           |
     | (calculate + report) |
     +---------+-----------+
               |
     +---------v-----------+
     | .aptl/reports/*.json |
     +---------------------+
```

### 2.4 State Directory Convention

The `.aptl/` directory in the project root holds all runtime state. It is
created on first use and should be added to `.gitignore`.

```
.aptl/
  session.json                              # Current active scenario (if any)
  events/
    recon-nmap-scan_2026-02-16T14-30-00.jsonl
  reports/
    recon-nmap-scan_2026-02-16T14-45-00.json
```

**Rationale**: Keeping state in the project directory (not `~/.aptl/`) means
state is scoped to the lab instance. Multiple clones can run independent
scenarios without collision.

---

## 3. Data Models

### 3.1 Scenario Definition Schema (Pydantic v2)

All models use `ConfigDict(extra="forbid")` to catch typos in YAML files --
matching `LabSettings` in `config.py`.

```python
# src/aptl/core/scenarios.py

from enum import Enum
from typing import Annotated, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator

class Difficulty(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

class ScenarioMode(str, Enum):
    RED = "red"
    BLUE = "blue"
    PURPLE = "purple"

class MitreReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tactics: list[str] = []
    techniques: list[str] = []

class ScenarioMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    description: str
    version: str = "1.0.0"
    author: str = ""
    difficulty: Difficulty
    estimated_minutes: int = Field(gt=0, le=480)
    tags: list[str] = []
    mitre_attack: MitreReference = MitreReference()

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        """Enforce slug format: lowercase alphanumeric, hyphens only."""
        import re
        if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$", v) or "--" in v:
            raise ValueError(
                f"Scenario id '{v}' must be a lowercase slug "
                "(e.g., 'recon-nmap-scan')"
            )
        return v

class PreconditionType(str, Enum):
    EXEC = "exec"
    FILE = "file"

class Precondition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: PreconditionType
    container: str
    description: str = ""
    # For type=exec
    command: Optional[str] = None
    # For type=file
    path: Optional[str] = None
    content: Optional[str] = None

    @model_validator(mode="after")
    def validate_fields_for_type(self) -> "Precondition":
        if self.type == PreconditionType.EXEC and not self.command:
            raise ValueError("Precondition type 'exec' requires 'command'")
        if self.type == PreconditionType.FILE:
            if not self.path:
                raise ValueError("Precondition type 'file' requires 'path'")
            if self.content is None:
                raise ValueError("Precondition type 'file' requires 'content'")
        return self

class ContainerRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid")
    required: list[str]

class Hint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: int = Field(ge=1, le=5)
    text: str
    point_penalty: int = Field(default=0, ge=0)

class ObjectiveType(str, Enum):
    MANUAL = "manual"
    WAZUH_ALERT = "wazuh_alert"
    COMMAND_OUTPUT = "command_output"
    FILE_EXISTS = "file_exists"

class WazuhAlertValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: dict  # Elasticsearch query DSL
    min_matches: int = Field(default=1, ge=1)
    time_window_seconds: int = Field(default=300, ge=10, le=3600)

class CommandOutputValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    container: str
    command: str
    contains: list[str] = []
    regex: Optional[str] = None

class FileExistsValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    container: str
    path: str
    contains: Optional[str] = None

class Objective(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    description: str
    type: ObjectiveType
    points: int = Field(ge=0, le=1000)
    hints: list[Hint] = []
    # Validation config (required for non-manual types)
    wazuh_alert: Optional[WazuhAlertValidation] = None
    command_output: Optional[CommandOutputValidation] = None
    file_exists: Optional[FileExistsValidation] = None

    @model_validator(mode="after")
    def validate_has_validation_for_type(self) -> "Objective":
        """Non-manual objectives must have matching validation config."""
        type_to_field = {
            ObjectiveType.WAZUH_ALERT: "wazuh_alert",
            ObjectiveType.COMMAND_OUTPUT: "command_output",
            ObjectiveType.FILE_EXISTS: "file_exists",
        }
        if self.type != ObjectiveType.MANUAL:
            field_name = type_to_field[self.type]
            if getattr(self, field_name) is None:
                raise ValueError(
                    f"Objective type '{self.type.value}' requires "
                    f"'{field_name}' validation config"
                )
        return self

class ObjectiveSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    red: list[Objective] = []
    blue: list[Objective] = []

    @model_validator(mode="after")
    def validate_not_empty(self) -> "ObjectiveSet":
        if not self.red and not self.blue:
            raise ValueError("Scenario must have at least one objective")
        return self

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "ObjectiveSet":
        all_ids = [o.id for o in self.red] + [o.id for o in self.blue]
        duplicates = [id for id in all_ids if all_ids.count(id) > 1]
        if duplicates:
            raise ValueError(
                f"Duplicate objective ids: {set(duplicates)}"
            )
        return self

class TimeBonusConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    max_bonus: int = Field(default=0, ge=0)
    decay_after_minutes: int = Field(default=10, ge=1)

class ScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    time_bonus: TimeBonusConfig = TimeBonusConfig()
    passing_score: int = Field(default=0, ge=0)
    max_score: int = Field(default=0, ge=0)

class ScenarioDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metadata: ScenarioMetadata
    mode: ScenarioMode
    containers: ContainerRequirements
    preconditions: list[Precondition] = []
    objectives: ObjectiveSet
    scoring: ScoringConfig = ScoringConfig()
```

### 3.2 Event Types

```python
# src/aptl/core/events.py

from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field

class EventType(str, Enum):
    SCENARIO_STARTED = "scenario_started"
    SCENARIO_STOPPED = "scenario_stopped"
    PRECONDITION_APPLIED = "precondition_applied"
    PRECONDITION_FAILED = "precondition_failed"
    OBJECTIVE_COMPLETED = "objective_completed"
    OBJECTIVE_FAILED = "objective_failed"
    ALERT_MATCHED = "alert_matched"
    HINT_REQUESTED = "hint_requested"
    EVALUATION_RUN = "evaluation_run"

@dataclass
class Event:
    event_type: EventType
    scenario_id: str
    timestamp: str  # ISO 8601, always UTC
    data: dict = field(default_factory=dict)
```

### 3.3 Session State

```python
# src/aptl/core/session.py

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

class SessionState(str, Enum):
    IDLE = "idle"
    ACTIVE = "active"
    EVALUATING = "evaluating"
    COMPLETED = "completed"

@dataclass
class ActiveSession:
    scenario_id: str
    state: SessionState
    started_at: str  # ISO 8601
    events_file: str  # Relative path within .aptl/
    hints_used: dict[str, int] = field(default_factory=dict)  # objective_id -> hint_level
    completed_objectives: list[str] = field(default_factory=list)
```

### 3.4 Objective Results

```python
# src/aptl/core/objectives.py

from enum import Enum
from dataclasses import dataclass
from typing import Optional

class ObjectiveStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class ObjectiveResult:
    objective_id: str
    status: ObjectiveStatus
    points_awarded: int = 0
    details: str = ""
    completed_at: Optional[str] = None  # ISO 8601

@dataclass
class EvaluationResult:
    results: list[ObjectiveResult]
    all_complete: bool
    evaluated_at: str  # ISO 8601
```

### 3.5 Scoring

```python
# src/aptl/core/scoring.py

from dataclasses import dataclass, field

@dataclass
class ScoreBreakdown:
    objective_scores: dict[str, int]  # objective_id -> points
    time_bonus: int = 0
    hint_penalties: int = 0
    total: int = 0
    max_possible: int = 0
    passing: bool = False

@dataclass
class ScenarioReport:
    scenario_id: str
    scenario_name: str
    difficulty: str
    mode: str
    started_at: str
    finished_at: str
    duration_seconds: float
    score: ScoreBreakdown
    objective_results: list[dict]  # Serialized ObjectiveResults
    events: list[dict]  # Serialized Events
    hints_used: dict[str, int]
```

---

## 4. Module Specifications

### 4.1 `src/aptl/core/scenarios.py` -- Scenario Models & Loading

**Responsibility**: Define the Pydantic schema for scenario YAML files. Load,
parse, and validate scenario definitions. Discover scenario files in a
directory.

**Public API**:

```python
def load_scenario(path: Path) -> ScenarioDefinition:
    """Load and validate a scenario definition from a YAML file.

    Args:
        path: Path to a .yaml scenario file.

    Returns:
        Validated ScenarioDefinition.

    Raises:
        FileNotFoundError: If the file does not exist.
        ScenarioValidationError: If YAML is malformed or fails Pydantic validation.
    """

def find_scenarios(search_dir: Path) -> list[Path]:
    """Find all .yaml files in a directory (non-recursive).

    Args:
        search_dir: Directory to search.

    Returns:
        Sorted list of paths to .yaml files.
    """

def validate_scenario_containers(
    scenario: ScenarioDefinition,
    config: AptlConfig,
) -> list[str]:
    """Check that all containers required by a scenario are enabled.

    Args:
        scenario: The scenario to check.
        config: Current APTL configuration.

    Returns:
        List of required containers that are not enabled. Empty means OK.
    """
```

**Logging**: DEBUG for file discovery, INFO for successful load, WARNING for
skipped files, ERROR via exceptions.

**Error handling**: Wraps `yaml.YAMLError` and `pydantic.ValidationError` into
`ScenarioValidationError` with context (file path, line number if available).

---

### 4.2 `src/aptl/core/events.py` -- Event Timeline

**Responsibility**: Provide an append-only event log for scenario execution.
Persist events as JSONL (one JSON object per line) for streaming reads and
crash safety.

**Public API**:

```python
class EventLog:
    """Append-only event log backed by a JSONL file."""

    def __init__(self, path: Path) -> None:
        """Initialize the event log.

        Creates parent directories if needed. Opens the file for
        append on first write.

        Args:
            path: Path to the .jsonl file.
        """

    def append(self, event: Event) -> None:
        """Append an event to the log.

        Writes a single JSON line and flushes immediately for
        crash safety.

        Args:
            event: The event to record.
        """

    def read_all(self) -> list[Event]:
        """Read all events from the log file.

        Returns:
            List of Events in chronological order.

        Raises:
            FileNotFoundError: If the log file does not exist.
        """

    def query_by_type(self, event_type: EventType) -> list[Event]:
        """Filter events by type.

        Args:
            event_type: The type to filter for.

        Returns:
            Matching events in chronological order.
        """
```

**File format**: One JSON object per line. Each line is a serialized `Event`:

```jsonl
{"event_type":"scenario_started","scenario_id":"recon-nmap-scan","timestamp":"2026-02-16T14:30:00Z","data":{"mode":"red"}}
{"event_type":"precondition_applied","scenario_id":"recon-nmap-scan","timestamp":"2026-02-16T14:30:01Z","data":{"type":"exec","container":"victim","command":"systemctl start apache2"}}
```

---

### 4.3 `src/aptl/core/session.py` -- Session State Management

**Responsibility**: Track the active scenario session. Persist state to disk
so CLI commands across separate invocations share context. Enforce valid state
transitions.

**Public API**:

```python
class ScenarioSession:
    """Manages active scenario state across CLI invocations."""

    def __init__(self, state_dir: Path) -> None:
        """Initialize session manager.

        Args:
            state_dir: Path to the .aptl/ directory.
        """

    def is_active(self) -> bool:
        """Check if a scenario is currently active."""

    def get_active(self) -> Optional[ActiveSession]:
        """Load the current active session from disk.

        Returns:
            The active session, or None if no scenario is running.
        """

    def start(
        self,
        scenario: ScenarioDefinition,
        events_file: Path,
    ) -> ActiveSession:
        """Start a new scenario session.

        Creates the session file and returns the new session.

        Args:
            scenario: The scenario being started.
            events_file: Path to the events JSONL file.

        Returns:
            The newly created ActiveSession.

        Raises:
            ScenarioStateError: If a scenario is already active.
        """

    def record_hint(self, objective_id: str, hint_level: int) -> None:
        """Record that a hint was used for an objective.

        Args:
            objective_id: The objective the hint is for.
            hint_level: The hint level revealed.

        Raises:
            ScenarioStateError: If no scenario is active.
        """

    def record_objective_complete(self, objective_id: str) -> None:
        """Record that an objective was completed.

        Args:
            objective_id: The completed objective.

        Raises:
            ScenarioStateError: If no scenario is active.
        """

    def finish(self) -> ActiveSession:
        """Mark the current session as completed and return it.

        Returns:
            The completed session with final state.

        Raises:
            ScenarioStateError: If no scenario is active.
        """

    def clear(self) -> None:
        """Remove the session file. Used after report generation."""
```

**State transitions**:

```
IDLE --(start)--> ACTIVE --(evaluate)--> EVALUATING --(finish)--> COMPLETED --(clear)--> IDLE
                    |                                                  ^
                    +----(stop early)----------------------------------+
```

**Persistence format** (`session.json`):

```json
{
  "scenario_id": "recon-nmap-scan",
  "state": "active",
  "started_at": "2026-02-16T14:30:00Z",
  "events_file": "events/recon-nmap-scan_2026-02-16T14-30-00.jsonl",
  "hints_used": {"scan-discovery": 1},
  "completed_objectives": []
}
```

---

### 4.4 `src/aptl/core/observer.py` -- Wazuh Alert Observer

**Responsibility**: Query the Wazuh Indexer (OpenSearch) API to check for
alerts matching objective criteria. Provides both one-shot queries and a
background polling thread for continuous observation.

**Public API**:

```python
@dataclass
class WazuhConnection:
    """Connection parameters for the Wazuh Indexer API."""
    url: str  # e.g., "https://localhost:9200"
    username: str
    password: str
    verify_ssl: bool = False

def query_wazuh_alerts(
    conn: WazuhConnection,
    query: dict,
    index_pattern: str = "wazuh-alerts-4.x-*",
    size: int = 100,
) -> list[dict]:
    """Execute an Elasticsearch query against the Wazuh Indexer.

    Uses urllib.request to make an HTTPS POST with basic auth.

    Args:
        conn: Wazuh connection parameters.
        query: Elasticsearch query DSL body.
        index_pattern: Index pattern to search.
        size: Maximum number of results.

    Returns:
        List of hit documents (the '_source' of each hit).

    Raises:
        ObserverError: If the query fails (network, auth, query syntax).
    """

def check_alert_objective(
    conn: WazuhConnection,
    validation: WazuhAlertValidation,
    scenario_start_time: str,
) -> ObjectiveResult:
    """Check if a wazuh_alert objective has been satisfied.

    Builds a time-bounded query using the validation config and
    scenario start time, executes it, and checks if the minimum
    match count is met.

    Args:
        conn: Wazuh connection parameters.
        validation: The objective's WazuhAlertValidation config.
        scenario_start_time: ISO 8601 timestamp of scenario start.

    Returns:
        ObjectiveResult with COMPLETED or PENDING status.
    """
```

**Implementation notes**:

- Uses `urllib.request.Request` with `ssl.create_default_context()` where
  `check_hostname=False` and `verify_mode=ssl.CERT_NONE` for self-signed certs.
  This matches the `curl -k` pattern in `services.py`.
- Basic auth via `base64`-encoded `Authorization` header.
- Response parsed with `json.loads()`.
- All network errors wrapped in `ObserverError` with original exception chained.

**Why not subprocess curl**: The Elasticsearch query bodies are complex nested
JSON. Building them as curl arguments is fragile and hard to test. `urllib` is
stdlib, zero-dependency, and straightforward to mock in tests.

**Why not httpx/requests**: Minimizes dependency surface. `urllib` is sufficient
for the query patterns needed (POST with JSON body, basic auth, skip TLS
verification). If future features need connection pooling or async, `httpx`
can replace `urllib` in a single module without API changes.

---

### 4.5 `src/aptl/core/objectives.py` -- Objective Evaluation

**Responsibility**: Evaluate objectives against their validation criteria.
Dispatches to the appropriate checker based on `ObjectiveType`.

**Public API**:

```python
def evaluate_objective(
    objective: Objective,
    *,
    wazuh_conn: Optional[WazuhConnection] = None,
    scenario_start_time: str = "",
    project_dir: Optional[Path] = None,
) -> ObjectiveResult:
    """Evaluate a single objective.

    Dispatches to the appropriate checker based on objective type:
    - MANUAL: Always returns PENDING (requires explicit user completion)
    - WAZUH_ALERT: Queries Wazuh via observer
    - COMMAND_OUTPUT: Executes command in container via docker exec
    - FILE_EXISTS: Checks file existence in container via docker exec

    Args:
        objective: The objective to evaluate.
        wazuh_conn: Wazuh connection (required for wazuh_alert type).
        scenario_start_time: When the scenario started (for time-bounded queries).
        project_dir: Project directory (for docker exec commands).

    Returns:
        ObjectiveResult with current status.

    Raises:
        ValueError: If required parameters are missing for the objective type.
    """

def evaluate_all(
    objectives: list[Objective],
    *,
    wazuh_conn: Optional[WazuhConnection] = None,
    scenario_start_time: str = "",
    project_dir: Optional[Path] = None,
    completed_ids: Optional[set[str]] = None,
) -> EvaluationResult:
    """Evaluate all objectives, skipping already-completed ones.

    Args:
        objectives: All objectives to evaluate.
        wazuh_conn: Wazuh connection parameters.
        scenario_start_time: Scenario start timestamp.
        project_dir: Project directory.
        completed_ids: Set of objective IDs already completed (skip these).

    Returns:
        EvaluationResult with per-objective results.
    """
```

**Command/file validation**: Uses `subprocess.run(["docker", "exec", ...])`,
matching the pattern in `services.py:check_manager_api_ready()`.

---

### 4.6 `src/aptl/core/scoring.py` -- Scoring & Reports

**Responsibility**: Calculate scores from objective results and generate
structured after-action reports.

**Public API**:

```python
def calculate_score(
    objectives: list[Objective],
    results: list[ObjectiveResult],
    scoring_config: ScoringConfig,
    elapsed_seconds: float,
    hints_used: dict[str, int],
) -> ScoreBreakdown:
    """Calculate the scenario score.

    Scoring rules:
    1. Each completed objective awards its defined points.
    2. Time bonus: if enabled and all objectives complete, awards
       (max_bonus * remaining_fraction) where remaining_fraction
       decreases linearly from 1.0 to 0.0 over decay_after_minutes.
    3. Hint penalties: each hint used deducts hint.point_penalty from
       the objective's score (floor at 0).
    4. Total = sum(objective_scores) + time_bonus - hint_penalties.
    5. Passing = total >= scoring_config.passing_score.

    Args:
        objectives: All scenario objectives.
        results: Evaluation results for each objective.
        scoring_config: Scoring configuration from the scenario.
        elapsed_seconds: Time elapsed since scenario start.
        hints_used: Map of objective_id -> highest hint level used.

    Returns:
        ScoreBreakdown with full details.
    """

def generate_report(
    scenario: ScenarioDefinition,
    session: ActiveSession,
    results: list[ObjectiveResult],
    events: list[Event],
    score: ScoreBreakdown,
) -> ScenarioReport:
    """Generate a structured after-action report.

    Args:
        scenario: The scenario definition.
        session: The completed session.
        results: Final objective results.
        events: Full event timeline.
        score: Calculated score.

    Returns:
        ScenarioReport ready for serialization.
    """

def write_report(report: ScenarioReport, path: Path) -> None:
    """Write a report to a JSON file.

    Args:
        report: The report to write.
        path: Output file path.
    """
```

**Time bonus formula**:
```
if elapsed_seconds < decay_after_minutes * 60:
    remaining = 1.0 - (elapsed_seconds / (decay_after_minutes * 60))
    bonus = int(max_bonus * remaining)
else:
    bonus = 0
```

---

### 4.7 `src/aptl/cli/scenario.py` -- CLI Commands

**Responsibility**: Thin CLI layer that wires user commands to core modules.
Follows the exact pattern of `cli/lab.py`.

```python
app = typer.Typer(help="Scenario management.")
```

**Commands**:

| Command | Description | Core calls |
|---------|-------------|------------|
| `aptl scenario list` | List available scenarios with name, difficulty, mode, tags | `find_scenarios()`, `load_scenario()` |
| `aptl scenario show <name>` | Show full details of a scenario | `load_scenario()` |
| `aptl scenario validate <path>` | Validate a scenario YAML file | `load_scenario()` |
| `aptl scenario start <name>` | Start a scenario: apply preconditions, init session | `load_scenario()`, `session.start()`, apply preconditions |
| `aptl scenario status` | Show active scenario, elapsed time, objective progress | `session.get_active()`, display state |
| `aptl scenario evaluate` | Run objective evaluation against live lab state | `evaluate_all()`, update session |
| `aptl scenario hint [objective_id]` | Reveal next hint for an objective | `session.record_hint()` |
| `aptl scenario stop` | Stop scenario, run final evaluation, generate report | `evaluate_all()`, `calculate_score()`, `generate_report()` |
| `aptl scenario complete <objective_id>` | Manually mark a MANUAL objective as complete | `session.record_objective_complete()` |

**Common options** (on relevant commands):

```python
project_dir: Path = typer.Option(
    Path("."), "--project-dir", "-d",
    help="Path to the APTL project directory.",
)
scenarios_dir: Path = typer.Option(
    None, "--scenarios-dir", "-s",
    help="Path to scenarios directory. Defaults to <project-dir>/scenarios.",
)
```

**Output format**: Uses `typer.echo()` for structured text output, consistent
with existing CLI commands. Rich tables for `list` command via `rich.table.Table`
(Rich is already a dependency).

---

### 4.8 Registration in Main CLI

```python
# src/aptl/cli/main.py -- add one line:
from aptl.cli import lab, config, container, scenario

app.add_typer(scenario.app, name="scenario")
```

---

## 5. Exception Hierarchy

```python
# src/aptl/core/scenarios.py (at the top, before models)

class ScenarioError(Exception):
    """Base exception for all scenario operations."""

class ScenarioNotFoundError(ScenarioError):
    """A scenario file or ID could not be found."""

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        super().__init__(f"Scenario not found: {identifier}")

class ScenarioValidationError(ScenarioError):
    """A scenario definition failed validation.

    Attributes:
        path: The file that failed validation (if applicable).
        details: Detailed validation error messages.
    """

    def __init__(self, message: str, path: Optional[Path] = None) -> None:
        self.path = path
        self.details = message
        prefix = f"{path}: " if path else ""
        super().__init__(f"{prefix}{message}")

class ScenarioStateError(ScenarioError):
    """An invalid state transition was attempted.

    Examples: starting a scenario when one is already active,
    stopping when none is active.
    """

class ObserverError(ScenarioError):
    """The Wazuh observation bus encountered an error.

    Wraps network errors, authentication failures, and query
    syntax errors from the Wazuh Indexer API.
    """
```

**Pattern**: Matches `ContainerNotFoundError` in `health.py` -- custom
exceptions with typed attributes, inheriting from a module-level base class.

---

## 6. Logging Strategy

Every module follows the existing pattern:

```python
from aptl.utils.logging import get_logger
log = get_logger("scenarios")  # -> "aptl.scenarios"
```

| Level | Usage |
|-------|-------|
| `DEBUG` | File discovery, query payloads, state transitions, validation details |
| `INFO` | Scenario loaded, session started/stopped, evaluation complete, report written |
| `WARNING` | Non-critical failures (precondition failed but non-blocking, hint penalty applied) |
| `ERROR` | Only via exceptions (not logged directly -- the CLI layer handles display) |

**Sensitive data**: Wazuh credentials are never logged, even at DEBUG. Query
payloads are logged at DEBUG but credentials are masked.

---

## 7. New Dependency

```toml
# pyproject.toml -- add to dependencies:
"PyYAML>=6.0",
```

**Rationale**: Scenario definitions are human-authored configuration. YAML is
the standard format for security tooling (SIGMA rules, Falco rules, Ansible
playbooks, Kubernetes manifests). JSON is viable but significantly less
readable for multi-line descriptions, nested structures, and inline comments.

`PyYAML` is a stable, widely-used package with no transitive dependencies.

---

## 8. Example Scenario Files

### 8.1 `scenarios/recon-nmap-scan.yaml`

```yaml
metadata:
  id: recon-nmap-scan
  name: "Network Reconnaissance: Nmap Service Scan"
  description: >
    Perform network reconnaissance against the victim machine using Nmap.
    Discover running services and their versions. This is a beginner-level
    exercise covering the first phase of a penetration test.
  version: "1.0.0"
  author: "APTL"
  difficulty: beginner
  estimated_minutes: 15
  tags:
    - reconnaissance
    - nmap
    - network-scanning
  mitre_attack:
    tactics:
      - TA0043
    techniques:
      - T1046

mode: red

containers:
  required:
    - kali
    - victim
    - wazuh

preconditions:
  - type: file
    container: victim
    path: /var/www/html/flag.txt
    content: "FLAG{recon_complete_42}"
    description: "Plant flag for discovery"

objectives:
  red:
    - id: port-scan
      description: "Discover all open TCP ports on the victim (172.20.0.20)"
      type: manual
      points: 50
      hints:
        - level: 1
          text: "Use nmap to scan the target IP"
          point_penalty: 10
        - level: 2
          text: "Try: nmap -sV 172.20.0.20"
          point_penalty: 25

    - id: service-identification
      description: "Identify the version of the SSH service running on the victim"
      type: manual
      points: 50
      hints:
        - level: 1
          text: "Use the -sV flag with nmap for version detection"
          point_penalty: 10

    - id: find-flag
      description: "Locate and read the flag hidden on the victim's web server"
      type: command_output
      points: 100
      command_output:
        container: kali
        command: "cat /tmp/captured-flag.txt"
        contains:
          - "FLAG{recon_complete_42}"
      hints:
        - level: 1
          text: "The flag is on a web server. What port do web servers typically use?"
          point_penalty: 15
        - level: 2
          text: "Try: curl http://172.20.0.20/flag.txt"
          point_penalty: 30

  blue: []

scoring:
  time_bonus:
    enabled: true
    max_bonus: 50
    decay_after_minutes: 10
  passing_score: 100
  max_score: 250
```

### 8.2 `scenarios/detect-brute-force.yaml`

```yaml
metadata:
  id: detect-brute-force
  name: "Blue Team: Detect SSH Brute Force"
  description: >
    A brute force SSH attack is occurring against the victim machine.
    Your task is to detect the attack using Wazuh alerts and create a
    custom detection rule for enhanced monitoring.
  version: "1.0.0"
  author: "APTL"
  difficulty: intermediate
  estimated_minutes: 30
  tags:
    - detection
    - brute-force
    - ssh
    - wazuh-rules
  mitre_attack:
    tactics:
      - TA0006
    techniques:
      - T1110.001

mode: purple

containers:
  required:
    - kali
    - victim
    - wazuh

preconditions: []

objectives:
  red:
    - id: brute-force-ssh
      description: "Execute an SSH brute force attack against the victim"
      type: manual
      points: 50
      hints:
        - level: 1
          text: "Use hydra to attempt SSH login with common credentials"
          point_penalty: 10
        - level: 2
          text: "Try: hydra -l labadmin -P /usr/share/wordlists/rockyou.txt ssh://172.20.0.20"
          point_penalty: 25

  blue:
    - id: detect-auth-failures
      description: "Confirm that Wazuh is generating alerts for failed SSH logins"
      type: wazuh_alert
      points: 75
      wazuh_alert:
        query:
          bool:
            must:
              - match:
                  rule.groups: authentication_failed
              - match:
                  agent.ip: "172.20.0.20"
        min_matches: 5
        time_window_seconds: 600
      hints:
        - level: 1
          text: "Check the Wazuh Dashboard for authentication alerts"
          point_penalty: 15

    - id: identify-attacker-ip
      description: "Identify the source IP address of the brute force attack"
      type: manual
      points: 75
      hints:
        - level: 1
          text: "Look at the srcip field in Wazuh alerts"
          point_penalty: 15

scoring:
  time_bonus:
    enabled: true
    max_bonus: 50
    decay_after_minutes: 20
  passing_score: 150
  max_score: 250
```

---

## 9. Test Strategy

### 9.1 Conventions

Follow existing test patterns exactly:
- `pytest` with class-based grouping (`class TestXxx:`)
- Fixtures in `conftest.py` (shared) and inline (module-specific)
- `pytest-mock` for subprocess/network mocking
- Import from module inside test methods (matching `test_config.py` pattern)
- Google-style docstrings on every test method

### 9.2 Test Modules

| Module | Tests | Key areas |
|--------|-------|-----------|
| `test_scenarios.py` | ~25 | Model validation (valid/invalid YAML), field validators, loading, file discovery, container validation |
| `test_events.py` | ~12 | Event creation, JSONL append/read, query by type, empty log handling, corrupted file handling |
| `test_session.py` | ~15 | State transitions, persistence round-trip, invalid transitions, concurrent access guards |
| `test_observer.py` | ~12 | Query building, response parsing, auth header construction, error wrapping, timeout handling |
| `test_objectives.py` | ~15 | Each objective type evaluation, missing validation config, skip-completed logic |
| `test_scoring.py` | ~12 | Score calculation, time bonus formula, hint penalties, passing threshold, report generation |
| `test_cli_scenario.py` | ~10 | Command wiring, output format, error display |
| **Total** | **~101** | |

### 9.3 Fixture Additions to `conftest.py`

```python
@pytest.fixture
def sample_scenario_dict() -> dict:
    """Minimal valid scenario as a dictionary."""
    return {
        "metadata": {
            "id": "test-scenario",
            "name": "Test Scenario",
            "description": "A test scenario",
            "difficulty": "beginner",
            "estimated_minutes": 10,
        },
        "mode": "red",
        "containers": {"required": ["kali", "victim"]},
        "objectives": {
            "red": [
                {
                    "id": "test-obj",
                    "description": "A test objective",
                    "type": "manual",
                    "points": 100,
                }
            ],
            "blue": [],
        },
    }

@pytest.fixture
def sample_scenario_yaml(tmp_path: Path, sample_scenario_dict: dict) -> Path:
    """Write a valid scenario YAML file and return its path."""
    import yaml
    path = tmp_path / "test-scenario.yaml"
    path.write_text(yaml.dump(sample_scenario_dict, default_flow_style=False))
    return path

@pytest.fixture
def aptl_state_dir(tmp_path: Path) -> Path:
    """Provide a temporary .aptl/ state directory."""
    state_dir = tmp_path / ".aptl"
    state_dir.mkdir()
    return state_dir
```

### 9.4 Mocking Strategy

| External dependency | Mock target | Notes |
|---|---|---|
| Wazuh Indexer API | `urllib.request.urlopen` | Return canned JSON responses |
| Docker exec (command/file checks) | `subprocess.run` | Match existing `mock_subprocess` fixture |
| File system (YAML loading) | `tmp_path` fixture | Real files in temp directory |
| Clock (time bonus) | `time.monotonic` / `datetime.now` | Freeze time for deterministic scoring |

---

## 10. Implementation Phases

### Phase 1: Schema & Loading (`scenarios.py`)
- All Pydantic models from Section 3.1
- Exception classes from Section 5
- `load_scenario()`, `find_scenarios()`, `validate_scenario_containers()`
- `test_scenarios.py` (~25 tests)
- Two example YAML files

**Deliverable**: `aptl scenario validate path/to/file.yaml` works.

### Phase 2: Event System (`events.py`)
- `Event`, `EventType`, `EventLog`
- JSONL read/write
- `test_events.py` (~12 tests)

**Deliverable**: Append-only event log with query support.

### Phase 3: Session State (`session.py`)
- `ScenarioSession`, `ActiveSession`, `SessionState`
- JSON persistence, state transitions
- `test_session.py` (~15 tests)

**Deliverable**: Session create/load/update/clear across CLI invocations.

### Phase 4: Observer (`observer.py`)
- `WazuhConnection`, `query_wazuh_alerts()`, `check_alert_objective()`
- urllib-based HTTP client
- `test_observer.py` (~12 tests)

**Deliverable**: One-shot Wazuh alert queries.

### Phase 5: Objectives (`objectives.py`)
- `evaluate_objective()`, `evaluate_all()`
- Dispatcher for all `ObjectiveType` variants
- `test_objectives.py` (~15 tests)

**Deliverable**: Full objective evaluation pipeline.

### Phase 6: Scoring (`scoring.py`)
- `calculate_score()`, `generate_report()`, `write_report()`
- Time bonus formula, hint penalties
- `test_scoring.py` (~12 tests)

**Deliverable**: Score calculation and JSON report output.

### Phase 7: CLI (`cli/scenario.py`)
- All commands from Section 4.7
- Registration in `main.py`
- `test_cli_scenario.py` (~10 tests)

**Deliverable**: Full `aptl scenario` command group.

### Phase 8: Integration & Polish
- Add `PyYAML` to `pyproject.toml`
- Add `.aptl/` to `.gitignore`
- Create `scenarios/` directory with example files
- Run full test suite, verify no regressions

**Deliverable**: Complete, tested, documented feature.

---

## 11. Files Changed / Created

### New Files

| File | Purpose |
|---|---|
| `src/aptl/core/scenarios.py` | Pydantic models, loading, validation |
| `src/aptl/core/events.py` | Event types, EventLog, JSONL persistence |
| `src/aptl/core/session.py` | Session state management |
| `src/aptl/core/observer.py` | Wazuh alert queries |
| `src/aptl/core/objectives.py` | Objective evaluation engine |
| `src/aptl/core/scoring.py` | Scoring and report generation |
| `src/aptl/cli/scenario.py` | CLI command group |
| `tests/test_scenarios.py` | Scenario model tests |
| `tests/test_events.py` | Event system tests |
| `tests/test_session.py` | Session state tests |
| `tests/test_observer.py` | Observer tests |
| `tests/test_objectives.py` | Objective evaluation tests |
| `tests/test_scoring.py` | Scoring tests |
| `tests/test_cli_scenario.py` | CLI tests |
| `scenarios/recon-nmap-scan.yaml` | Example red team scenario |
| `scenarios/detect-brute-force.yaml` | Example purple team scenario |

### Modified Files

| File | Change |
|---|---|
| `src/aptl/cli/main.py` | Add `scenario` Typer sub-app |
| `pyproject.toml` | Add `PyYAML>=6.0` dependency |
| `.gitignore` | Add `.aptl/` directory |
| `tests/conftest.py` | Add scenario-related fixtures |

---

## 12. Acceptance Criteria

1. `aptl scenario list` displays available scenarios from `scenarios/` directory
   with name, difficulty, mode, and tags in a formatted table.

2. `aptl scenario validate scenarios/recon-nmap-scan.yaml` succeeds with no
   errors for valid files, and produces clear error messages with file path
   and field location for invalid files.

3. `aptl scenario start recon-nmap-scan` applies preconditions, creates a
   session file in `.aptl/session.json`, initializes an event log, and prints
   scenario briefing to stdout.

4. `aptl scenario status` (during an active scenario) shows elapsed time,
   active objectives, and completion state.

5. `aptl scenario evaluate` queries Wazuh and checks command/file objectives,
   printing results per-objective and updating session state.

6. `aptl scenario hint port-scan` reveals the next unrevealed hint for the
   specified objective, records the hint usage for scoring penalty.

7. `aptl scenario stop` runs a final evaluation, calculates the score with
   time bonus and hint penalties, generates a JSON report in `.aptl/reports/`,
   and prints a summary to stdout.

8. All ~101 new tests pass. Existing 174 tests pass with no regressions.

9. No new dependencies beyond `PyYAML`.

10. All modules follow existing codebase conventions: Pydantic v2 with
    `extra="forbid"`, dataclasses for results, `get_logger()` per module,
    Google-style docstrings, full type hints, explicit exception handling.
