"""Orchestration models — Injects, Events, Scripts, Stories.

Implements the OCR SDL exercise orchestration pipeline:
  Stories -> Scripts -> Events -> { Conditions, Injects }

Scripts use human-readable duration strings (e.g., ``"10min 2 sec"``).
"""

import re
from typing import Optional

from pydantic import Field, field_validator, model_validator

from aptl.core.sdl._base import SDLModel
from aptl.core.sdl._source import Source

# Duration parsing: supports combinations like "1h 30min", "10 min 2 sec"
_DURATION_UNITS = {
    "w": 604_800,
    "week": 604_800,
    "weeks": 604_800,
    "d": 86_400,
    "day": 86_400,
    "days": 86_400,
    "h": 3_600,
    "hr": 3_600,
    "hour": 3_600,
    "hours": 3_600,
    "m": 60,
    "min": 60,
    "mins": 60,
    "minute": 60,
    "minutes": 60,
    "s": 1,
    "sec": 1,
    "secs": 1,
    "second": 1,
    "seconds": 1,
    "ms": 0.001,
}

_DURATION_TOKEN = re.compile(
    r"(\d+(?:_\d+)*(?:\.\d+)?)\s*("
    + "|".join(sorted(_DURATION_UNITS, key=len, reverse=True))
    + r")\b",
    re.IGNORECASE,
)


def parse_duration(value: str | int | float) -> int:
    """Parse a human-readable duration string to seconds.

    Accepts integers/floats (treated as seconds) or strings like
    ``"10min 2 sec"``, ``"1 week 1day 1h"``, ``"0"``.
    """
    if isinstance(value, (int, float)):
        return int(value)

    value_str = str(value).strip().replace("_", "")
    if not value_str or value_str == "0":
        return 0

    if value_str.isdigit():
        return int(value_str)

    total = 0.0
    found = False
    for match in _DURATION_TOKEN.finditer(value_str):
        found = True
        amount = float(match.group(1))
        unit = match.group(2).lower()
        total += amount * _DURATION_UNITS[unit]

    if not found:
        raise ValueError(f"Invalid duration: {value!r}")

    return int(total)


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
    start_time: int = Field(ge=0)
    end_time: int = Field(ge=0)
    speed: float = Field(gt=0)
    events: dict[str, int] = Field(min_length=1)
    description: str = ""

    @field_validator("start_time", "end_time", mode="before")
    @classmethod
    def parse_time(cls, v: str | int | float) -> int:
        return parse_duration(v)

    @field_validator("events", mode="before")
    @classmethod
    def parse_event_times(cls, v: dict) -> dict[str, int]:
        if isinstance(v, dict):
            return {k: parse_duration(t) for k, t in v.items()}
        return v

    @model_validator(mode="after")
    def validate_time_bounds(self) -> "Script":
        if self.end_time < self.start_time:
            raise ValueError(
                f"Script end_time ({self.end_time}s) must be >= "
                f"start_time ({self.start_time}s)"
            )
        for event_name, event_time in self.events.items():
            if event_time < self.start_time or event_time > self.end_time:
                raise ValueError(
                    f"Event '{event_name}' time ({event_time}s) is outside "
                    f"script bounds [{self.start_time}s, {self.end_time}s]"
                )
        return self


class Story(SDLModel):
    """Top-level exercise orchestration — a group of scripts."""

    name: str = ""
    speed: float = Field(default=1.0, ge=1.0)
    scripts: list[str] = Field(min_length=1)
    description: str = ""
