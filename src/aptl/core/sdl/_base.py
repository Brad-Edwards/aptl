"""Base model configuration for the SDL package.

All SDL models inherit from SDLModel, which enforces strict
validation (extra fields forbidden) and populates by field name.
Case-insensitive enum matching is enabled via use_enum_values.
"""

from pydantic import BaseModel, ConfigDict


class SDLModel(BaseModel):
    """Base for all SDL Pydantic models."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )


def normalize_enum_value(v: str) -> str:
    """Normalize a string for case-insensitive enum matching."""
    return v.lower() if isinstance(v, str) else v
