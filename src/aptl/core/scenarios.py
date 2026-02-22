"""Scenario definition models, loading, and validation.

Provides Pydantic v2 models for scenario YAML files, YAML loading with
error wrapping, scenario discovery, and container requirement validation.
"""

import re
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aptl.core.config import AptlConfig
from aptl.core.detection import ExpectedDetection
from aptl.utils.logging import get_logger

log = get_logger("scenarios")

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Difficulty(str, Enum):
    """Scenario difficulty level."""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class ScenarioMode(str, Enum):
    """Which team roles are involved in the scenario."""

    RED = "red"
    BLUE = "blue"
    PURPLE = "purple"


class PreconditionType(str, Enum):
    """Type of precondition action to apply before scenario start."""

    EXEC = "exec"
    FILE = "file"


class ObjectiveType(str, Enum):
    """How an objective is validated."""

    MANUAL = "manual"
    WAZUH_ALERT = "wazuh_alert"
    COMMAND_OUTPUT = "command_output"
    FILE_EXISTS = "file_exists"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class MitreReference(BaseModel):
    """MITRE ATT&CK tactic and technique references."""

    model_config = ConfigDict(extra="forbid")

    tactics: list[str] = []
    techniques: list[str] = []


class ScenarioMetadata(BaseModel):
    """Descriptive metadata for a scenario."""

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
        """Enforce slug format: lowercase alphanumeric with hyphens."""
        if not _SLUG_PATTERN.match(v):
            raise ValueError(
                f"Scenario id '{v}' must be a lowercase slug "
                "(e.g., 'recon-nmap-scan'). Use only lowercase "
                "alphanumeric characters and single hyphens."
            )
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure name is non-empty."""
        if not v or not v.strip():
            raise ValueError("Scenario name must not be empty")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Ensure description is non-empty."""
        if not v or not v.strip():
            raise ValueError("Scenario description must not be empty")
        return v


class Precondition(BaseModel):
    """An action to apply before scenario start."""

    model_config = ConfigDict(extra="forbid")

    type: PreconditionType
    container: str
    description: str = ""
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None

    @model_validator(mode="after")
    def validate_fields_for_type(self) -> "Precondition":
        """Ensure required fields are present for the precondition type."""
        if self.type == PreconditionType.EXEC and not self.command:
            raise ValueError("Precondition type 'exec' requires 'command'")
        if self.type == PreconditionType.FILE:
            if not self.path:
                raise ValueError("Precondition type 'file' requires 'path'")
            if self.content is None:
                raise ValueError("Precondition type 'file' requires 'content'")
        return self


class ContainerRequirements(BaseModel):
    """Which containers must be enabled for this scenario."""

    model_config = ConfigDict(extra="forbid")

    required: list[str]

    @field_validator("required")
    @classmethod
    def validate_required(cls, v: list[str]) -> list[str]:
        """Ensure at least one container is required."""
        if not v:
            raise ValueError("Scenario must require at least one container")
        return v


class Hint(BaseModel):
    """A progressive hint for an objective."""

    model_config = ConfigDict(extra="forbid")

    level: int = Field(ge=1, le=5)
    text: str
    point_penalty: int = Field(default=0, ge=0)

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        """Ensure hint text is non-empty."""
        if not v or not v.strip():
            raise ValueError("Hint text must not be empty")
        return v


class WazuhAlertValidation(BaseModel):
    """Validation config for wazuh_alert objective type."""

    model_config = ConfigDict(extra="forbid")

    query: dict[str, Any]
    min_matches: int = Field(default=1, ge=1)
    time_window_seconds: int = Field(default=300, ge=10, le=3600)


class CommandOutputValidation(BaseModel):
    """Validation config for command_output objective type."""

    model_config = ConfigDict(extra="forbid")

    container: str
    command: str
    contains: list[str] = []
    regex: Optional[str] = None


class FileExistsValidation(BaseModel):
    """Validation config for file_exists objective type."""

    model_config = ConfigDict(extra="forbid")

    container: str
    path: str
    contains: Optional[str] = None


class Objective(BaseModel):
    """A single objective within a scenario."""

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    type: ObjectiveType
    points: int = Field(ge=0, le=1000)
    hints: list[Hint] = []
    wazuh_alert: Optional[WazuhAlertValidation] = None
    command_output: Optional[CommandOutputValidation] = None
    file_exists: Optional[FileExistsValidation] = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        """Enforce slug format for objective IDs."""
        if not _SLUG_PATTERN.match(v):
            raise ValueError(
                f"Objective id '{v}' must be a lowercase slug "
                "(e.g., 'port-scan')"
            )
        return v

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

    @model_validator(mode="after")
    def validate_hint_levels_unique(self) -> "Objective":
        """Hint levels must be unique and sequential starting from 1."""
        if not self.hints:
            return self
        levels = [h.level for h in self.hints]
        if len(levels) != len(set(levels)):
            raise ValueError("Hint levels must be unique")
        return self


class ObjectiveSet(BaseModel):
    """Red and blue team objectives for a scenario."""

    model_config = ConfigDict(extra="forbid")

    red: list[Objective] = []
    blue: list[Objective] = []

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "ObjectiveSet":
        """Objective IDs must be unique across red and blue."""
        all_ids = [o.id for o in self.red] + [o.id for o in self.blue]
        seen: set[str] = set()
        duplicates: set[str] = set()
        for obj_id in all_ids:
            if obj_id in seen:
                duplicates.add(obj_id)
            seen.add(obj_id)
        if duplicates:
            raise ValueError(f"Duplicate objective ids: {duplicates}")
        return self

    def all_objectives(self) -> list[Objective]:
        """Return all objectives (red + blue) in order."""
        return self.red + self.blue


class TimeBonusConfig(BaseModel):
    """Configuration for time-based bonus scoring."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    max_bonus: int = Field(default=0, ge=0)
    decay_after_minutes: int = Field(default=10, ge=1)


class ScoringConfig(BaseModel):
    """Scoring parameters for a scenario."""

    model_config = ConfigDict(extra="forbid")

    time_bonus: TimeBonusConfig = TimeBonusConfig()
    passing_score: int = Field(default=0, ge=0)
    max_score: int = Field(default=0, ge=0)


class AttackStep(BaseModel):
    """A single attack step combining technique info with expected detections."""

    model_config = ConfigDict(extra="forbid")

    step_number: int = Field(ge=1)
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    target: str
    commands: list[str] = []
    prerequisites: list[str] = []
    expected_detections: list[ExpectedDetection] = []
    investigation_hints: list[str] = []
    remediation: list[str] = []


class ScenarioDefinition(BaseModel):
    """Complete scenario definition loaded from a YAML file."""

    model_config = ConfigDict(extra="forbid")

    metadata: ScenarioMetadata
    mode: ScenarioMode
    containers: ContainerRequirements
    preconditions: list[Precondition] = []
    objectives: ObjectiveSet = Field(default_factory=lambda: ObjectiveSet(red=[], blue=[]))
    scoring: ScoringConfig = ScoringConfig()
    attack_chain: str = ""
    steps: list[AttackStep] = []

    @model_validator(mode="after")
    def validate_has_content(self) -> "ScenarioDefinition":
        """Scenario must have steps or objectives (or both)."""
        has_steps = bool(self.steps)
        has_objectives = bool(self.objectives.red or self.objectives.blue)
        if not has_steps and not has_objectives:
            raise ValueError("Scenario must have steps or objectives (or both)")
        return self

    @model_validator(mode="after")
    def validate_mode_has_objectives(self) -> "ScenarioDefinition":
        """Scenario mode must match the objectives provided."""
        has_objectives = bool(self.objectives.red or self.objectives.blue)
        if not has_objectives:
            return self
        if self.mode == ScenarioMode.RED and not self.objectives.red:
            raise ValueError("Red mode scenario must have red objectives")
        if self.mode == ScenarioMode.BLUE and not self.objectives.blue:
            raise ValueError("Blue mode scenario must have blue objectives")
        if self.mode == ScenarioMode.PURPLE:
            if not self.objectives.red and not self.objectives.blue:
                raise ValueError(
                    "Purple mode scenario must have at least one objective"
                )
        return self

    @model_validator(mode="after")
    def validate_step_numbers_unique(self) -> "ScenarioDefinition":
        """Attack step numbers must be unique."""
        if not self.steps:
            return self
        numbers = [s.step_number for s in self.steps]
        if len(numbers) != len(set(numbers)):
            raise ValueError("Attack step numbers must be unique")
        return self


# ---------------------------------------------------------------------------
# Loading and discovery
# ---------------------------------------------------------------------------


def load_scenario(path: Path) -> ScenarioDefinition:
    """Load and validate a scenario definition from a YAML file.

    Args:
        path: Path to a .yaml scenario file.

    Returns:
        Validated ScenarioDefinition.

    Raises:
        FileNotFoundError: If the file does not exist.
        ScenarioValidationError: If YAML is malformed or fails validation.
    """
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {path}")

    raw = path.read_text().strip()
    if not raw:
        raise ScenarioValidationError("Scenario file is empty", path=path)

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ScenarioValidationError(
            f"Invalid YAML: {e}", path=path
        ) from e

    if not isinstance(data, dict):
        raise ScenarioValidationError(
            "Scenario file must contain a YAML mapping (not a scalar or list)",
            path=path,
        )

    try:
        scenario = ScenarioDefinition(**data)
    except Exception as e:
        raise ScenarioValidationError(str(e), path=path) from e

    log.info("Loaded scenario '%s' from %s", scenario.metadata.id, path)
    return scenario


def find_scenarios(search_dir: Path) -> list[Path]:
    """Find all .yaml scenario files in a directory (non-recursive).

    Args:
        search_dir: Directory to search.

    Returns:
        Sorted list of paths to .yaml files. Empty if directory
        does not exist.
    """
    if not search_dir.is_dir():
        log.debug("Scenarios directory does not exist: %s", search_dir)
        return []

    paths = sorted(search_dir.glob("*.yaml"))
    log.debug("Found %d scenario files in %s", len(paths), search_dir)
    return paths


def validate_scenario_containers(
    scenario: ScenarioDefinition,
    config: AptlConfig,
) -> list[str]:
    """Check that all containers required by a scenario are enabled.

    Args:
        scenario: The scenario to check.
        config: Current APTL configuration.

    Returns:
        List of required containers that are not enabled. Empty means
        all requirements are satisfied.
    """
    enabled = set(config.containers.enabled_profiles())
    required = set(scenario.containers.required)
    missing = sorted(required - enabled)
    if missing:
        log.warning(
            "Scenario '%s' requires disabled containers: %s",
            scenario.metadata.id,
            ", ".join(missing),
        )
    return missing
