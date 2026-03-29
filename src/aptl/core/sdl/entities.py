"""Entity models — organizations, teams, and people.

Entities form a recursive hierarchy with exercise roles
(White/Green/Red/Blue). Nested entities are referenced via
dot-notation (e.g., ``blue-team.bob``).
"""

from enum import Enum
from typing import Optional

from pydantic import Field, field_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value


class ExerciseRole(str, Enum):
    """Role in the exercise."""

    WHITE = "white"
    GREEN = "green"
    RED = "red"
    BLUE = "blue"


class Entity(SDLModel):
    """An organizational unit, team, or person in the exercise.

    Entities can nest recursively. Flattened names use dot-notation:
    ``blue-team.bob`` refers to the ``bob`` entity nested inside
    ``blue-team``.
    """

    name: str = ""
    description: str = ""
    role: Optional[ExerciseRole] = None

    @field_validator("role", mode="before")
    @classmethod
    def normalize_role(cls, v):
        return normalize_enum_value(v) if v is not None else v
    mission: str = ""
    categories: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    tlos: list[str] = Field(default_factory=list)
    events: list[str] = Field(default_factory=list)
    entities: dict[str, "Entity"] = Field(default_factory=dict)


def flatten_entities(
    entities: dict[str, Entity], prefix: str = ""
) -> dict[str, Entity]:
    """Flatten a recursive entity hierarchy into dot-notation names.

    Returns a dict mapping ``"parent.child.grandchild"`` to the
    leaf Entity objects.
    """
    result: dict[str, Entity] = {}
    for key, entity in entities.items():
        full_name = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
        result[full_name] = entity
        if entity.entities:
            result.update(flatten_entities(entity.entities, full_name))
    return result
