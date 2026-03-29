"""Variable models — scenario parameterization.

Adapted from CACAO v2.0 playbook_variables. Named variables with
types, defaults, and descriptions that can be referenced throughout
the scenario via ``${var_name}`` substitution syntax.

Variables are NOT resolved at parse time. The SDL parser stores
``${var_name}`` strings as-is in the model. Resolution happens
at instantiation time when a backend deploys the scenario.
"""

from enum import Enum
from typing import Union

from pydantic import Field, field_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value


class VariableType(str, Enum):
    """Data type of a variable."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    NUMBER = "number"


class Variable(SDLModel):
    """A named variable for scenario parameterization.

    Variables define configurable parameters with types, defaults,
    and optional value constraints. They're referenced in other
    sections via ``${variable_name}`` syntax.
    """

    type: VariableType
    default: Union[str, int, float, bool, None] = None
    description: str = ""
    allowed_values: list[Union[str, int, float, bool]] = Field(default_factory=list)
    required: bool = False

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return normalize_enum_value(v)
