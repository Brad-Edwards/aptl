"""Objective models — APTL scenario objectives with auto-evaluation.

Extends the OCR SDL with APTL's objective system: typed objectives
(manual, wazuh_alert, command_output, file_exists) with validation
configs, hints, and scoring.

Ported from the original ``aptl.core.scenarios`` module.
"""

import re
from enum import Enum
from typing import Any, Optional

from pydantic import Field, field_validator, model_validator

from aptl.core.sdl._base import SDLModel

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class ObjectiveType(str, Enum):
    """How an objective is validated."""

    MANUAL = "manual"
    WAZUH_ALERT = "wazuh_alert"
    COMMAND_OUTPUT = "command_output"
    FILE_EXISTS = "file_exists"


class Hint(SDLModel):
    """A progressive hint for an objective."""

    level: int = Field(ge=1, le=5)
    text: str
    point_penalty: int = Field(default=0, ge=0)

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Hint text must not be empty")
        return v


class WazuhAlertValidation(SDLModel):
    """Validation config for wazuh_alert objective type."""

    query: dict[str, Any]
    min_matches: int = Field(default=1, ge=1)
    time_window_seconds: int = Field(default=300, ge=10, le=3600)


class CommandOutputValidation(SDLModel):
    """Validation config for command_output objective type."""

    container: str
    command: str
    contains: list[str] = Field(default_factory=list)
    regex: Optional[str] = None


class FileExistsValidation(SDLModel):
    """Validation config for file_exists objective type."""

    container: str
    path: str
    contains: Optional[str] = None


class Objective(SDLModel):
    """A single objective within a scenario."""

    id: str
    description: str
    type: ObjectiveType
    points: int = Field(ge=0, le=1000)
    hints: list[Hint] = Field(default_factory=list)
    wazuh_alert: Optional[WazuhAlertValidation] = None
    command_output: Optional[CommandOutputValidation] = None
    file_exists: Optional[FileExistsValidation] = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not _SLUG_PATTERN.match(v):
            raise ValueError(
                f"Objective id '{v}' must be a lowercase slug "
                "(e.g., 'port-scan')"
            )
        return v

    @model_validator(mode="after")
    def validate_has_validation_for_type(self) -> "Objective":
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
        if not self.hints:
            return self
        levels = [h.level for h in self.hints]
        if len(levels) != len(set(levels)):
            raise ValueError("Hint levels must be unique")
        return self


class ObjectiveSet(SDLModel):
    """Red and blue team objectives for a scenario."""

    red: list[Objective] = Field(default_factory=list)
    blue: list[Objective] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "ObjectiveSet":
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


class TimeBonusConfig(SDLModel):
    """Configuration for time-based bonus scoring."""

    enabled: bool = False
    max_bonus: int = Field(default=0, ge=0)
    decay_after_minutes: int = Field(default=10, ge=1)


class ScoringConfig(SDLModel):
    """Scoring parameters for a scenario."""

    time_bonus: TimeBonusConfig = Field(default_factory=TimeBonusConfig)
    passing_score: int = Field(default=0, ge=0)
    max_score: int = Field(default=0, ge=0)
