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

from pydantic import Field, field_validator, model_validator

from mcp_scenario.sdl._base import SDLModel, normalize_enum_value


class VariableType(str, Enum):
    """Data type of a variable."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    NUMBER = "number"


def _matches_variable_type(value: object, variable_type: VariableType) -> bool:
    """Return whether a concrete value matches the declared variable type."""
    if variable_type == VariableType.STRING:
        return isinstance(value, str)
    if variable_type == VariableType.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if variable_type == VariableType.BOOLEAN:
        return isinstance(value, bool)
    if variable_type == VariableType.NUMBER:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


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

    @model_validator(mode="after")
    def validate_typed_values(self) -> "Variable":
        """Defaults and allowed values must match the declared type."""
        if (
            self.default is not None
            and not _matches_variable_type(self.default, self.type)
        ):
            raise ValueError(
                f"default must match variable type '{self.type.value}'"
            )

        for value in self.allowed_values:
            if not _matches_variable_type(value, self.type):
                raise ValueError(
                    f"allowed_values must match variable type '{self.type.value}'"
                )

        if (
            self.allowed_values
            and self.default is not None
            and self.default not in self.allowed_values
        ):
            raise ValueError(
                "default must be one of allowed_values when allowed_values is set"
            )

        return self
