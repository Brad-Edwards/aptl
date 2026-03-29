"""Scoring models — Metrics, Evaluations, TLOs, and Goals.

Implements the OCR SDL scoring pipeline:
  Conditions -> Metrics -> Evaluations -> TLOs -> Goals

Metrics are either manual (human-graded) or conditional (automated
via condition checks). Evaluations group metrics with pass/fail
thresholds. TLOs link to evaluations. Goals compose TLOs.
"""

from enum import Enum
from typing import Optional

from pydantic import Field, field_validator, model_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value


class MetricType(str, Enum):
    """How a metric is scored."""

    MANUAL = "manual"
    CONDITIONAL = "conditional"


class Metric(SDLModel):
    """A scoring metric — either manual or conditional.

    Manual metrics may require artifact submission. Conditional
    metrics reference a condition that produces the score.
    """

    name: str = ""
    type: MetricType = Field(alias="type")
    artifact: Optional[bool] = None

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return normalize_enum_value(v)
    max_score: int = Field(ge=1)
    condition: Optional[str] = None
    description: str = ""

    @model_validator(mode="after")
    def validate_type_fields(self) -> "Metric":
        if self.type == MetricType.MANUAL:
            if self.condition is not None:
                raise ValueError("Manual metric cannot have a condition")
        elif self.type == MetricType.CONDITIONAL:
            if self.condition is None:
                raise ValueError("Conditional metric requires a condition")
            if self.artifact is not None:
                raise ValueError("Conditional metric cannot have artifact flag")
        return self


class MinScore(SDLModel):
    """Pass/fail threshold — either absolute points or percentage.

    Shorthand: ``min-score: 50`` (interpreted as percentage).
    Longhand: ``min-score: {absolute: 50}`` or ``{percentage: 75}``.
    """

    absolute: Optional[int] = Field(default=None, ge=0)
    percentage: Optional[int] = Field(default=None, ge=0, le=100)

    @model_validator(mode="after")
    def validate_exclusive(self) -> "MinScore":
        if self.absolute is not None and self.percentage is not None:
            raise ValueError(
                "MinScore cannot have both 'absolute' and 'percentage'"
            )
        if self.absolute is None and self.percentage is None:
            raise ValueError(
                "MinScore must have either 'absolute' or 'percentage'"
            )
        return self


class Evaluation(SDLModel):
    """A group of metrics with a pass/fail threshold."""

    name: str = ""
    description: str = ""
    metrics: list[str] = Field(min_length=1)
    min_score: MinScore


class TLO(SDLModel):
    """Training Learning Objective — linked to an evaluation."""

    name: str = ""
    description: str = ""
    evaluation: str


class Goal(SDLModel):
    """High-level goal composed of TLOs."""

    name: str = ""
    description: str = ""
    tlos: list[str] = Field(min_length=1)
