"""Node models — VMs and network switches.

Ports the OCR SDL Node/VM/Switch/Resources/Role structs with
backend-agnostic Source references.
"""

import re
from enum import Enum
from typing import Optional

from pydantic import Field, field_validator, model_validator

from aptl.core.sdl._base import SDLModel, normalize_enum_value
from aptl.core.sdl._source import Source

MAX_NODE_NAME_LENGTH = 35

_BYTE_UNITS = {
    "b": 1,
    "kb": 1_000,
    "kib": 1_024,
    "mb": 1_000_000,
    "mib": 1_048_576,
    "gb": 1_000_000_000,
    "gib": 1_073_741_824,
    "tb": 1_000_000_000_000,
    "tib": 1_099_511_627_776,
}

_RAM_PATTERN = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(" + "|".join(_BYTE_UNITS) + r")\s*$",
    re.IGNORECASE,
)


def parse_ram(value: str | int) -> int:
    """Parse a human-readable RAM string to bytes.

    Accepts bare integers (treated as bytes) or strings like
    ``"4 GiB"``, ``"2048 MiB"``, ``"512mb"``.
    """
    if isinstance(value, int):
        return value
    value_str = str(value).strip()
    if value_str.isdigit():
        return int(value_str)
    match = _RAM_PATTERN.match(value_str)
    if not match:
        raise ValueError(
            f"Invalid RAM value: {value_str!r}. "
            f"Use a number with a unit (e.g., '4 GiB', '2048 MiB')."
        )
    amount = float(match.group(1))
    unit = match.group(2).lower()
    return int(amount * _BYTE_UNITS[unit])


class NodeType(str, Enum):
    """Whether a node is a virtual machine or network switch."""

    VM = "vm"
    SWITCH = "switch"


class Resources(SDLModel):
    """Compute resources for a VM node."""

    ram: int = Field(ge=1, description="RAM in bytes (parsed from human-readable)")
    cpu: int = Field(ge=1, description="Number of CPU cores")

    @field_validator("ram", mode="before")
    @classmethod
    def parse_ram_value(cls, v: str | int) -> int:
        return parse_ram(v)


class Role(SDLModel):
    """A named role on a VM with optional entity assignments.

    Shorthand: ``admin: "username"`` (just the username string).
    Longhand: ``admin: {username: "admin", entities: ["blue-team.bob"]}``.
    """

    username: str
    entities: list[str] = Field(default_factory=list)


class VM(SDLModel):
    """Virtual machine configuration."""

    source: Optional[Source] = None
    resources: Resources
    features: dict[str, str] = Field(
        default_factory=dict,
        description="Feature name -> role name mapping",
    )
    conditions: dict[str, str] = Field(
        default_factory=dict,
        description="Condition name -> role name mapping",
    )
    injects: dict[str, str] = Field(
        default_factory=dict,
        description="Inject name -> role name mapping",
    )
    vulnerabilities: list[str] = Field(default_factory=list)
    roles: dict[str, Role] = Field(default_factory=dict)


class OSFamily(str, Enum):
    """Operating system family. Vocabulary from OCSF Device.os."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    FREEBSD = "freebsd"
    OTHER = "other"


class AssetValueLevel(str, Enum):
    """CIA triad value level. Adapted from CybORG ConfidentialityValue."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetValue(SDLModel):
    """CIA triad asset valuation for scoring and risk assessment."""

    confidentiality: AssetValueLevel = AssetValueLevel.MEDIUM
    integrity: AssetValueLevel = AssetValueLevel.MEDIUM
    availability: AssetValueLevel = AssetValueLevel.MEDIUM


class ServicePort(SDLModel):
    """A network service exposed by a node. From OCSF NetworkEndpoint."""

    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    name: str = ""
    description: str = ""


class Switch(SDLModel):
    """Network switch — a pure connectivity node with no compute."""

    pass


class Node(SDLModel):
    """A scenario node — either a VM or a Switch.

    The ``type`` field determines which variant is active. VM fields
    are only valid when type is VM; Switch nodes carry no extra data.
    """

    type: NodeType = Field(alias="type")
    description: str = ""
    source: Optional[Source] = None

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, v: str) -> str:
        return normalize_enum_value(v)
    resources: Optional[Resources] = None
    os: Optional[OSFamily] = None
    os_version: str = ""
    features: dict[str, str] = Field(default_factory=dict)
    conditions: dict[str, str] = Field(default_factory=dict)
    injects: dict[str, str] = Field(default_factory=dict)
    vulnerabilities: list[str] = Field(default_factory=list)
    roles: dict[str, Role] = Field(default_factory=dict)
    services: list[ServicePort] = Field(default_factory=list)
    asset_value: Optional[AssetValue] = None

    @field_validator("os", mode="before")
    @classmethod
    def normalize_os(cls, v):
        return normalize_enum_value(v) if v is not None else v

    @model_validator(mode="after")
    def validate_type_constraints(self) -> "Node":
        """Switch nodes cannot have source, resources, features, etc."""
        if self.type == NodeType.SWITCH:
            if self.source is not None:
                raise ValueError("Switch nodes cannot have a source")
            if self.resources is not None:
                raise ValueError("Switch nodes cannot have resources")
        return self
