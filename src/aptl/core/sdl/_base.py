"""Base model configuration and shared helpers for the SDL package."""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict


class SDLModel(BaseModel):
    """Base for all SDL Pydantic models."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )


_VARIABLE_REF_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_-]*)\}$")


def is_variable_ref(v: Any) -> bool:
    """Return whether ``v`` is a full ``${var_name}`` placeholder."""
    return isinstance(v, str) and _VARIABLE_REF_RE.fullmatch(v) is not None


def extract_variable_name(v: str) -> str | None:
    """Return the referenced variable name, if ``v`` is a placeholder."""
    match = _VARIABLE_REF_RE.fullmatch(v) if isinstance(v, str) else None
    return match.group(1) if match else None


def normalize_enum_value(v: str) -> str:
    """Normalize a string for case-insensitive enum matching."""
    if is_variable_ref(v):
        return v
    return v.lower() if isinstance(v, str) else v


def parse_int_or_var(
    value: Any,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    field_name: str = "value",
) -> int | str:
    """Parse an integer field while allowing ``${var}`` placeholders."""
    if is_variable_ref(value) or value is None:
        return value
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        parsed = int(value.strip())
    else:
        raise ValueError(f"{field_name} must be an integer")

    if minimum is not None and parsed < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{field_name} must be <= {maximum}")
    return parsed


def parse_float_or_var(
    value: Any,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    field_name: str = "value",
) -> float | str:
    """Parse a float field while allowing ``${var}`` placeholders."""
    if is_variable_ref(value) or value is None:
        return value
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a number")
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str):
        try:
            parsed = float(value.strip())
        except ValueError as e:
            raise ValueError(f"{field_name} must be a number") from e
    else:
        raise ValueError(f"{field_name} must be a number")

    if minimum is not None and parsed < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{field_name} must be <= {maximum}")
    return parsed


def parse_bool_or_var(value: Any, *, field_name: str = "value") -> bool | str:
    """Parse a boolean field while allowing ``${var}`` placeholders."""
    if is_variable_ref(value) or value is None:
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        truthy = {"true", "1", "yes", "on"}
        falsy = {"false", "0", "no", "off"}
        if lowered in truthy:
            return True
        if lowered in falsy:
            return False
    raise ValueError(f"{field_name} must be a boolean")
