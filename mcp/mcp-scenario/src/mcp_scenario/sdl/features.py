"""Feature models — software deployed onto VMs.

Features are composable configuration units (Service, Configuration,
or Artifact) with dependency graphs. The validator detects cycles.
"""

from enum import Enum
from typing import Optional

from pydantic import Field, field_validator

from mcp_scenario.sdl._base import SDLModel, normalize_enum_value
from mcp_scenario.sdl._source import Source


class FeatureType(str, Enum):
    """Kind of feature deployed to a VM."""

    SERVICE = "service"
    CONFIGURATION = "configuration"
    ARTIFACT = "artifact"


class Feature(SDLModel):
    """A software artifact, service, or configuration deployed to a VM."""

    name: str = ""
    type: FeatureType = Field(alias="type")
    source: Optional[Source] = None

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return normalize_enum_value(v)
    dependencies: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    destination: str = ""
    description: str = ""
    environment: list[str] = Field(default_factory=list)
