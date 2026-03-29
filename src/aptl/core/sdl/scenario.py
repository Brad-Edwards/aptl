"""Top-level Scenario model combining all SDL sections.

The Scenario is the root object of the SDL. It merges the 14 OCR SDL
sections with APTL extensions (objectives, attack steps, defenses,
preconditions, metadata). Only ``name`` is required for an OCR-style
scenario; APTL legacy format requires ``metadata`` instead.
"""

import re
from enum import Enum
from typing import Any, Optional

from pydantic import Field, field_validator, model_validator

from aptl.core.sdl._base import SDLModel
from aptl.core.sdl.accounts import Account
from aptl.core.sdl.attacks import AttackStep, MitreReference
from aptl.core.sdl.conditions import Condition
from aptl.core.sdl.content import Content
from aptl.core.sdl.defenses import DefenseConfig
from aptl.core.sdl.entities import Entity
from aptl.core.sdl.features import Feature
from aptl.core.sdl.infrastructure import InfraNode
from aptl.core.sdl.nodes import Node
from aptl.core.sdl.objectives import ObjectiveSet, ScoringConfig
from aptl.core.sdl.orchestration import Event, Inject, Script, Story
from aptl.core.sdl.scoring import Evaluation, Goal, Metric, TLO
from aptl.core.sdl.vulnerabilities import Vulnerability

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


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


class Precondition(SDLModel):
    """An action to apply before scenario start."""

    type: PreconditionType
    container: str
    description: str = ""
    command: Optional[str] = None
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


class ContainerRequirements(SDLModel):
    """Which containers must be enabled for this scenario."""

    required: list[str]

    @field_validator("required")
    @classmethod
    def validate_required(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Scenario must require at least one container")
        return v


class ScenarioMetadata(SDLModel):
    """Descriptive metadata for an APTL scenario."""

    id: str
    name: str
    description: str
    version: str = "1.0.0"
    author: str = ""
    difficulty: Difficulty
    estimated_minutes: int = Field(gt=0, le=480)
    tags: list[str] = Field(default_factory=list)
    mitre_attack: MitreReference = Field(default_factory=MitreReference)

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not _SLUG_PATTERN.match(v):
            raise ValueError(
                f"Scenario id '{v}' must be a lowercase slug "
                "(e.g., 'recon-nmap-scan')"
            )
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Scenario name must not be empty")
        return v

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Scenario description must not be empty")
        return v


class Scenario(SDLModel):
    """Top-level scenario definition.

    Combines the 14 OCR SDL sections with APTL extensions. Supports
    two format styles:

    - **OCR-style**: ``name`` at top level, plus optional sections
    - **APTL legacy**: ``metadata`` block with ``id``, ``name``, etc.

    Both styles coexist. The parser detects and normalizes the format.
    """

    # --- OCR SDL: identity ---
    name: str = ""
    description: str = ""

    # --- OCR SDL: 14 sections ---
    nodes: dict[str, Node] = Field(default_factory=dict)
    infrastructure: dict[str, InfraNode] = Field(default_factory=dict)
    features: dict[str, Feature] = Field(default_factory=dict)
    conditions: dict[str, Condition] = Field(default_factory=dict)
    vulnerabilities: dict[str, Vulnerability] = Field(default_factory=dict)
    metrics: dict[str, Metric] = Field(default_factory=dict)
    evaluations: dict[str, Evaluation] = Field(default_factory=dict)
    tlos: dict[str, TLO] = Field(default_factory=dict)
    goals: dict[str, Goal] = Field(default_factory=dict)
    entities: dict[str, Entity] = Field(default_factory=dict)
    injects: dict[str, Inject] = Field(default_factory=dict)
    events: dict[str, Event] = Field(default_factory=dict)
    scripts: dict[str, Script] = Field(default_factory=dict)
    stories: dict[str, Story] = Field(default_factory=dict)

    # --- New sections (G1, G2) ---
    content: dict[str, Content] = Field(default_factory=dict)
    accounts: dict[str, Account] = Field(default_factory=dict)

    # --- APTL extensions ---
    metadata: Optional[ScenarioMetadata] = None
    mode: Optional[ScenarioMode] = None
    containers: Optional[ContainerRequirements] = None
    preconditions: list[Precondition] = Field(default_factory=list)
    objectives: ObjectiveSet = Field(
        default_factory=lambda: ObjectiveSet(red=[], blue=[])
    )
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    attack_chain: str = ""
    steps: list[AttackStep] = Field(default_factory=list)
    defenses: Optional[dict[str, Any] | DefenseConfig] = None

    @model_validator(mode="after")
    def validate_has_identity(self) -> "Scenario":
        """Scenario must have a name (OCR-style or via metadata)."""
        has_name = bool(self.name)
        has_metadata = self.metadata is not None
        if not has_name and not has_metadata:
            raise ValueError(
                "Scenario must have 'name' (OCR-style) or 'metadata' (APTL-style)"
            )
        return self

    @model_validator(mode="after")
    def validate_step_numbers_unique(self) -> "Scenario":
        if not self.steps:
            return self
        numbers = [s.step_number for s in self.steps]
        if len(numbers) != len(set(numbers)):
            raise ValueError("Attack step numbers must be unique")
        return self

    @model_validator(mode="after")
    def validate_mode_has_objectives(self) -> "Scenario":
        """APTL-style: scenario mode must match the objectives provided."""
        if self.mode is None:
            return self
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
    def validate_has_content(self) -> "Scenario":
        """APTL-style: scenario must have steps, objectives, or OCR content."""
        if self.metadata is None:
            return self  # OCR-style — content check is more relaxed
        has_steps = bool(self.steps)
        has_objectives = bool(self.objectives.red or self.objectives.blue)
        if not has_steps and not has_objectives:
            raise ValueError("Scenario must have steps or objectives (or both)")
        return self
