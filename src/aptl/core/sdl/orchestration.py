"""Orchestration models — Injects, Events, Scripts, Stories.

Implements the OCR SDL exercise orchestration pipeline:
  Stories -> Scripts -> Events -> { Conditions, Injects }

Scripts use OCR-compatible human-readable duration strings
(e.g., ``"10min 2 sec"``, ``"1 mon"``, ``"1 us"``).
"""

import math
import re
from decimal import Decimal, ROUND_CEILING
from enum import Enum
from typing import Optional

from pydantic import Field, field_validator, model_validator

from aptl.core.sdl._base import (
    SDLModel,
    is_variable_ref,
    normalize_enum_value,
    parse_float_or_var,
)
from aptl.core.sdl._source import Source

# OCR uses duration-str's fixed calendar conversions: 30d/month, 365d/year.
_DURATION_UNITS = {
    "y": Decimal("31536000"),
    "year": Decimal("31536000"),
    "years": Decimal("31536000"),
    "mon": Decimal("2592000"),
    "month": Decimal("2592000"),
    "months": Decimal("2592000"),
    "w": Decimal("604800"),
    "week": Decimal("604800"),
    "weeks": Decimal("604800"),
    "d": Decimal("86400"),
    "day": Decimal("86400"),
    "days": Decimal("86400"),
    "h": Decimal("3600"),
    "hr": Decimal("3600"),
    "hour": Decimal("3600"),
    "hours": Decimal("3600"),
    "m": Decimal("60"),
    "min": Decimal("60"),
    "mins": Decimal("60"),
    "minute": Decimal("60"),
    "minutes": Decimal("60"),
    "s": Decimal("1"),
    "sec": Decimal("1"),
    "secs": Decimal("1"),
    "second": Decimal("1"),
    "seconds": Decimal("1"),
    "ms": Decimal("0.001"),
    "msec": Decimal("0.001"),
    "millisecond": Decimal("0.001"),
    "milliseconds": Decimal("0.001"),
    "us": Decimal("0.000001"),
    "usec": Decimal("0.000001"),
    "usecond": Decimal("0.000001"),
    "microsecond": Decimal("0.000001"),
    "microseconds": Decimal("0.000001"),
    "ns": Decimal("0.000000001"),
    "nsec": Decimal("0.000000001"),
    "nanosecond": Decimal("0.000000001"),
    "nanoseconds": Decimal("0.000000001"),
}

_DURATION_NUMBER = re.compile(r"\d+(?:\.\d+)?")


def parse_duration(value: str | int | float) -> int | str:
    """Parse a human-readable duration string to seconds.

    Accepts integers/floats (treated as seconds) or strings like
    ``"10min 2 sec"``, ``"1 week 1day 1h"``, ``"1 mon"``, ``"1 us"``,
    ``"1m+30"``, ``"0"``.
    """
    if is_variable_ref(value):
        return value
    if isinstance(value, bool):
        raise ValueError(f"Invalid duration: {value!r}")
    if isinstance(value, (int, float)):
        if value < 0:
            raise ValueError(f"Invalid duration: {value!r}")
        if value == 0:
            return 0
        return math.ceil(value)

    value_str = str(value).strip()
    if not value_str:
        raise ValueError(f"Invalid duration: {value!r}")
    if value_str == "0":
        return 0

    normalized = (
        value_str.replace("_", "")
        .replace(" ", "")
        .replace("µ", "u")
        .lower()
    )

    if re.fullmatch(r"\d+(?:\.\d+)?", normalized):
        total = Decimal(normalized)
        return int(total.to_integral_value(rounding=ROUND_CEILING))

    total = Decimal("0")
    position = 0
    parsed_any = False
    units = sorted(_DURATION_UNITS, key=len, reverse=True)

    while position < len(normalized):
        if normalized[position] == "+":
            position += 1
            continue

        match = _DURATION_NUMBER.match(normalized, position)
        if match is None:
            raise ValueError(f"Invalid duration: {value!r}")

        parsed_any = True
        amount = Decimal(match.group(0))
        position = match.end()

        unit = None
        for candidate in units:
            if normalized.startswith(candidate, position):
                unit = candidate
                position += len(candidate)
                break

        # duration-str treats bare numbers as seconds
        multiplier = _DURATION_UNITS[unit] if unit else Decimal("1")
        total += amount * multiplier

    if not parsed_any:
        raise ValueError(f"Invalid duration: {value!r}")

    return int(total.to_integral_value(rounding=ROUND_CEILING))


class Inject(SDLModel):
    """An action injected between entities during an exercise."""

    name: str = ""
    source: Optional[Source] = None
    from_entity: str = ""
    to_entities: list[str] = Field(default_factory=list)
    tlos: list[str] = Field(default_factory=list)
    description: str = ""
    environment: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_entity_pairing(self) -> "Inject":
        has_from = bool(self.from_entity)
        has_to = bool(self.to_entities)
        if has_from != has_to:
            raise ValueError(
                "Inject must have both 'from_entity' and 'to_entities', "
                "or neither"
            )
        return self


class Event(SDLModel):
    """A triggered action combining conditions and injects."""

    name: str = ""
    source: Optional[Source] = None
    conditions: list[str] = Field(default_factory=list)
    injects: list[str] = Field(default_factory=list)
    description: str = ""


class Script(SDLModel):
    """A timed sequence of events.

    Time values are human-readable duration strings parsed to seconds.
    """

    name: str = ""
    start_time: int | str
    end_time: int | str
    speed: float | str
    events: dict[str, int | str] = Field(min_length=1)
    description: str = ""

    @field_validator("start_time", "end_time", mode="before")
    @classmethod
    def parse_time(cls, v: str | int | float) -> int | str:
        return parse_duration(v)

    @field_validator("speed", mode="before")
    @classmethod
    def parse_speed(cls, v: str | int | float) -> float | str:
        parsed = parse_float_or_var(v, minimum=0, field_name="speed")
        if isinstance(parsed, float) and parsed <= 0:
            raise ValueError("speed must be > 0")
        return parsed

    @field_validator("events", mode="before")
    @classmethod
    def parse_event_times(cls, v: dict) -> dict[str, int | str]:
        if isinstance(v, dict):
            return {k: parse_duration(t) for k, t in v.items()}
        return v

    @model_validator(mode="after")
    def validate_time_bounds(self) -> "Script":
        if (
            isinstance(self.start_time, int)
            and isinstance(self.end_time, int)
            and self.end_time < self.start_time
        ):
            raise ValueError(
                f"Script end_time ({self.end_time}s) must be >= "
                f"start_time ({self.start_time}s)"
            )
        for event_name, event_time in self.events.items():
            if not (
                isinstance(self.start_time, int)
                and isinstance(self.end_time, int)
                and isinstance(event_time, int)
            ):
                continue
            if event_time < self.start_time or event_time > self.end_time:
                raise ValueError(
                    f"Event '{event_name}' time ({event_time}s) is outside "
                    f"script bounds [{self.start_time}s, {self.end_time}s]"
                )
        return self


class Story(SDLModel):
    """Top-level exercise orchestration — a group of scripts."""

    name: str = ""
    speed: float | str = 1.0
    scripts: list[str] = Field(min_length=1)
    description: str = ""

    @field_validator("speed", mode="before")
    @classmethod
    def parse_speed(cls, v: str | int | float) -> float | str:
        return parse_float_or_var(v, minimum=1.0, field_name="speed")


class WorkflowStepType(str, Enum):
    """Control-flow node types for declarative experiment workflows."""

    OBJECTIVE = "objective"
    IF = "if"
    PARALLEL = "parallel"
    END = "end"


class WorkflowPredicate(SDLModel):
    """Branch predicate reusing objective-style success references."""

    conditions: list[str] = Field(default_factory=list)
    metrics: list[str] = Field(default_factory=list)
    evaluations: list[str] = Field(default_factory=list)
    tlos: list[str] = Field(default_factory=list)
    goals: list[str] = Field(default_factory=list)
    objectives: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_non_empty(self) -> "WorkflowPredicate":
        if any((
            self.conditions,
            self.metrics,
            self.evaluations,
            self.tlos,
            self.goals,
            self.objectives,
        )):
            return self
        raise ValueError(
            "Workflow predicate must reference at least one condition, "
            "metric, evaluation, TLO, goal, or objective"
        )


class WorkflowStep(SDLModel):
    """A node in a workflow graph."""

    type: WorkflowStepType = Field(alias="type")
    objective: str = ""
    next: str = ""
    when: WorkflowPredicate | None = None
    then_step: str = Field(default="", alias="then")
    else_step: str = Field(default="", alias="else")
    branches: list[str] = Field(default_factory=list)
    description: str = ""

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return normalize_enum_value(v)

    @model_validator(mode="after")
    def validate_type_specific_fields(self) -> "WorkflowStep":
        if self.type == WorkflowStepType.OBJECTIVE:
            if not self.objective:
                raise ValueError("Objective workflow step requires 'objective'")
            if self.when is not None or self.then_step or self.else_step or self.branches:
                raise ValueError(
                    "Objective workflow step only supports 'objective', "
                    "optional 'next', and 'description'"
                )
            return self

        if self.type == WorkflowStepType.IF:
            if self.when is None or not self.then_step or not self.else_step:
                raise ValueError(
                    "If workflow step requires 'when', 'then', and 'else'"
                )
            if self.objective or self.branches or self.next:
                raise ValueError(
                    "If workflow step only supports 'when', 'then', 'else', "
                    "and 'description'"
                )
            return self

        if self.type == WorkflowStepType.PARALLEL:
            if not self.branches:
                raise ValueError("Parallel workflow step requires 'branches'")
            if self.objective or self.when is not None or self.then_step or self.else_step:
                raise ValueError(
                    "Parallel workflow step only supports 'branches', "
                    "optional 'next', and 'description'"
                )
            if len(self.branches) != len(set(self.branches)):
                raise ValueError("Parallel workflow branches must be unique")
            return self

        if self.objective or self.next or self.when is not None or self.then_step or self.else_step or self.branches:
            raise ValueError(
                "End workflow step only supports 'type' and 'description'"
            )
        return self


class Workflow(SDLModel):
    """A declarative experiment control graph over objectives."""

    description: str = ""
    start: str
    steps: dict[str, WorkflowStep] = Field(min_length=1)
