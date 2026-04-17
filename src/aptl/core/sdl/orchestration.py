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
    parse_int_or_var,
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
    DECISION = "decision"
    SWITCH = "switch"
    PARALLEL = "parallel"
    JOIN = "join"
    RETRY = "retry"
    CALL = "call"
    END = "end"


class WorkflowStepOutcome(str, Enum):
    """Portable workflow-visible outcomes emitted by executable steps."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXHAUSTED = "exhausted"


class WorkflowStepStateRef(SDLModel):
    """Predicate reference to previously observed workflow step state."""

    step: str
    outcomes: list[WorkflowStepOutcome] = Field(min_length=1)
    min_attempts: int | str | None = Field(default=None, alias="min-attempts")

    @field_validator("min_attempts", mode="before")
    @classmethod
    def parse_min_attempts(cls, v: int | str | None) -> int | str | None:
        if v is None:
            return None
        return parse_int_or_var(v, minimum=1, field_name="min_attempts")

    @model_validator(mode="after")
    def validate_unique_outcomes(self) -> "WorkflowStepStateRef":
        if len(self.outcomes) != len(set(self.outcomes)):
            raise ValueError("Workflow step-state outcomes must be unique")
        return self


class WorkflowPredicate(SDLModel):
    """Branch predicate over runtime evaluation data and prior step state."""

    conditions: list[str] = Field(default_factory=list)
    metrics: list[str] = Field(default_factory=list)
    evaluations: list[str] = Field(default_factory=list)
    tlos: list[str] = Field(default_factory=list)
    goals: list[str] = Field(default_factory=list)
    objectives: list[str] = Field(default_factory=list)
    steps: list[WorkflowStepStateRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_non_empty(self) -> "WorkflowPredicate":
        if any((
            self.conditions,
            self.metrics,
            self.evaluations,
            self.tlos,
            self.goals,
            self.objectives,
            self.steps,
        )):
            return self
        raise ValueError(
            "Workflow predicate must reference at least one condition, "
            "metric, evaluation, TLO, goal, objective, or step state"
        )


class WorkflowSwitchCase(SDLModel):
    """One ordered branch case within a ``switch`` workflow step."""

    when: WorkflowPredicate
    next_step: str = Field(alias="next")
    description: str = ""


class WorkflowTimeoutPolicy(SDLModel):
    """Workflow-level timeout policy."""

    seconds: int | str

    @field_validator("seconds", mode="before")
    @classmethod
    def parse_seconds(cls, v: str | int | float) -> int | str:
        parsed = parse_duration(v)
        if isinstance(parsed, int) and parsed <= 0:
            raise ValueError("timeout seconds must be > 0")
        return parsed


class WorkflowCompensationMode(str, Enum):
    """Workflow-level compensation behavior."""

    AUTOMATIC = "automatic"
    DISABLED = "disabled"


class WorkflowCompensationTrigger(str, Enum):
    """Terminal workflow reasons that may trigger compensation."""

    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class WorkflowCompensationFailurePolicy(str, Enum):
    """How primary workflow status should treat compensation failures."""

    FAIL_WORKFLOW = "fail_workflow"
    RECORD_AND_CONTINUE = "record_and_continue"


class WorkflowCompensationPolicy(SDLModel):
    """Workflow-level compensation policy."""

    mode: WorkflowCompensationMode = WorkflowCompensationMode.DISABLED
    on: list[WorkflowCompensationTrigger] = Field(default_factory=list)
    failure_policy: WorkflowCompensationFailurePolicy = Field(
        default=WorkflowCompensationFailurePolicy.FAIL_WORKFLOW,
        alias="failure_policy",
    )
    order: str = "reverse_completion"

    @field_validator("order", mode="before")
    @classmethod
    def normalize_order(cls, v: object) -> str:
        if v is None:
            return "reverse_completion"
        return str(v)

    @model_validator(mode="after")
    def validate_policy(self) -> "WorkflowCompensationPolicy":
        if self.mode == WorkflowCompensationMode.AUTOMATIC and not self.on:
            raise ValueError(
                "Automatic workflow compensation requires at least one trigger in 'on'"
            )
        if self.order != "reverse_completion":
            raise ValueError(
                "Workflow compensation currently only supports order "
                "'reverse_completion'"
            )
        if len(self.on) != len(set(self.on)):
            raise ValueError("Workflow compensation triggers must be unique")
        return self


class WorkflowStep(SDLModel):
    """A named workflow step with explicit portable control semantics."""

    type: WorkflowStepType = Field(alias="type")
    objective: str = ""
    next: str = ""
    on_success: str = Field(default="", alias="on-success")
    on_failure: str = Field(default="", alias="on-failure")
    on_exhausted: str = Field(default="", alias="on-exhausted")
    when: WorkflowPredicate | None = None
    then_step: str = Field(default="", alias="then")
    else_step: str = Field(default="", alias="else")
    cases: list[WorkflowSwitchCase] = Field(default_factory=list)
    default_step: str = Field(default="", alias="default")
    branches: list[str] = Field(default_factory=list)
    join: str = ""
    workflow: str = ""
    compensate_with: str = Field(default="", alias="compensate-with")
    max_attempts: int | str | None = Field(default=None, alias="max-attempts")
    description: str = ""

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        normalized = normalize_enum_value(v)
        if normalized in {"if", "while"}:
            raise ValueError(
                f"workflow step type '{normalized}' is no longer supported; "
                "use 'decision' or 'retry' with explicit success/failure "
                "transitions instead"
            )
        return normalized

    @field_validator("max_attempts", mode="before")
    @classmethod
    def parse_max_attempts(cls, v: int | str | None) -> int | str | None:
        if v is None:
            return None
        return parse_int_or_var(v, minimum=1, field_name="max_attempts")

    @model_validator(mode="after")
    def validate_type_specific_fields(self) -> "WorkflowStep":
        if self.type == WorkflowStepType.OBJECTIVE:
            if not self.objective or not self.on_success:
                raise ValueError(
                    "Objective workflow step requires 'objective' and 'on-success'"
                )
            if (
                self.next
                or self.on_exhausted
                or self.when is not None
                or self.then_step
                or self.else_step
                or self.branches
                or self.join
                or self.max_attempts is not None
            ):
                raise ValueError(
                    "Objective workflow step only supports 'objective', "
                    "'on-success', optional 'on-failure', optional "
                    "'compensate-with', and 'description'"
                )
            return self

        if self.type == WorkflowStepType.DECISION:
            if self.when is None or not self.then_step or not self.else_step:
                raise ValueError(
                    "Decision workflow step requires 'when', 'then', and 'else'"
                )
            if (
                self.objective
                or self.next
                or self.on_success
                or self.on_failure
                or self.on_exhausted
                or self.branches
                or self.join
                or self.max_attempts is not None
                or self.compensate_with
            ):
                raise ValueError(
                    "Decision workflow step only supports 'when', 'then', "
                    "'else', and 'description'"
                )
            return self

        if self.type == WorkflowStepType.SWITCH:
            if not self.cases or not self.default_step:
                raise ValueError(
                    "Switch workflow step requires at least one 'case' and a "
                    "'default' target"
                )
            if (
                self.objective
                or self.next
                or self.on_success
                or self.on_failure
                or self.on_exhausted
                or self.when is not None
                or self.then_step
                or self.else_step
                or self.branches
                or self.join
                or self.workflow
                or self.max_attempts is not None
                or self.compensate_with
            ):
                raise ValueError(
                    "Switch workflow step only supports 'cases', 'default', "
                    "and 'description'"
                )
            return self

        if self.type == WorkflowStepType.PARALLEL:
            if len(self.branches) < 2 or not self.join:
                raise ValueError(
                    "Parallel workflow step requires at least two 'branches' "
                    "and a 'join'"
                )
            if (
                self.objective
                or self.when is not None
                or self.next
                or self.on_success
                or self.on_exhausted
                or self.then_step
                or self.else_step
                or self.max_attempts is not None
                or self.compensate_with
            ):
                raise ValueError(
                    "Parallel workflow step only supports 'branches', 'join', "
                    "optional 'on-failure', and 'description'"
                )
            if len(self.branches) != len(set(self.branches)):
                raise ValueError("Parallel workflow branches must be unique")
            return self

        if self.type == WorkflowStepType.JOIN:
            if not self.next:
                raise ValueError(
                    "Join workflow step requires 'next'"
                )
            if (
                self.objective
                or self.on_success
                or self.on_failure
                or self.on_exhausted
                or self.when is not None
                or self.then_step
                or self.else_step
                or self.branches
                or self.join
                or self.max_attempts is not None
                or self.compensate_with
            ):
                raise ValueError(
                    "Join workflow step only supports 'next' and 'description'"
                )
            return self

        if self.type == WorkflowStepType.RETRY:
            if (
                not self.objective
                or self.max_attempts is None
                or not self.on_success
            ):
                raise ValueError(
                    "Retry workflow step requires 'objective', 'max-attempts', "
                    "and 'on-success'"
                )
            if (
                self.next
                or self.when is not None
                or self.on_failure
                or self.then_step
                or self.else_step
                or self.branches
                or self.join
                or self.compensate_with
            ):
                raise ValueError(
                    "Retry workflow step only supports 'objective', "
                    "'max-attempts', 'on-success', optional 'on-exhausted', "
                    "and 'description'"
                )
            return self

        if self.type == WorkflowStepType.CALL:
            if not self.workflow or not self.on_success:
                raise ValueError(
                    "Call workflow step requires 'workflow' and 'on-success'"
                )
            if (
                self.objective
                or self.next
                or self.on_exhausted
                or self.when is not None
                or self.then_step
                or self.else_step
                or self.cases
                or self.default_step
                or self.branches
                or self.join
                or self.max_attempts is not None
            ):
                raise ValueError(
                    "Call workflow step only supports 'workflow', "
                    "'on-success', optional 'on-failure', optional "
                    "'compensate-with', and 'description'"
                )
            return self

        # END step
        if (
            self.objective
            or self.next
            or self.when is not None
            or self.on_success
            or self.on_failure
            or self.on_exhausted
            or self.then_step
            or self.else_step
            or self.cases
            or self.default_step
            or self.branches
            or self.join
            or self.workflow
            or self.max_attempts is not None
            or self.compensate_with
        ):
            raise ValueError(
                "End workflow step only supports 'type' and 'description'"
            )
        return self


class Workflow(SDLModel):
    """A declarative experiment control graph over objectives."""

    description: str = ""
    start: str
    timeout: WorkflowTimeoutPolicy | None = None
    compensation: WorkflowCompensationPolicy | None = None
    steps: dict[str, WorkflowStep] = Field(min_length=1)

    @field_validator("timeout", mode="before")
    @classmethod
    def parse_timeout(cls, v: object) -> object:
        if v is None or isinstance(v, WorkflowTimeoutPolicy):
            return v
        if isinstance(v, (int, float, str)):
            return {"seconds": v}
        return v

    @field_validator("compensation", mode="before")
    @classmethod
    def parse_compensation(cls, v: object) -> object:
        if v is None or isinstance(v, WorkflowCompensationPolicy):
            return v
        return v
