"""Node models — VMs and network switches.

Ports the OCR SDL Node/VM/Switch/Resources/Role structs with
backend-agnostic Source references.
"""

import re
from enum import Enum
from typing import Optional

from pydantic import Field, field_validator, model_validator

from mcp_scenario.sdl._base import (
    SDLModel,
    is_variable_ref,
    normalize_enum_value,
    parse_enum_or_var,
    parse_int_or_var,
)
from mcp_scenario.sdl._source import Source

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


def parse_ram(value: str | int) -> int | str:
    """Parse a human-readable RAM string to bytes.

    Accepts bare integers (treated as bytes) or strings like
    ``"4 GiB"``, ``"2048 MiB"``, ``"512mb"``.
    """
    if is_variable_ref(value):
        return value
    if isinstance(value, bool):
        raise ValueError("RAM must be a positive integer or human-readable size")
    if isinstance(value, int):
        if value < 1:
            raise ValueError("RAM must be >= 1 byte")
        return value
    value_str = str(value).strip()
    if value_str.isdigit():
        parsed = int(value_str)
        if parsed < 1:
            raise ValueError("RAM must be >= 1 byte")
        return parsed
    match = _RAM_PATTERN.match(value_str)
    if not match:
        raise ValueError(
            f"Invalid RAM value: {value_str!r}. "
            f"Use a number with a unit (e.g., '4 GiB', '2048 MiB')."
        )
    amount = float(match.group(1))
    unit = match.group(2).lower()
    parsed = int(amount * _BYTE_UNITS[unit])
    if parsed < 1:
        raise ValueError("RAM must be >= 1 byte")
    return parsed


class NodeType(str, Enum):
    """Whether a node is a virtual machine or network switch."""

    VM = "vm"
    SWITCH = "switch"


class Resources(SDLModel):
    """Compute resources for a VM node."""

    ram: int | str = Field(description="RAM in bytes (parsed from human-readable)")
    cpu: int | str = Field(description="Number of CPU cores")

    @field_validator("ram", mode="before")
    @classmethod
    def parse_ram_value(cls, v: str | int) -> int | str:
        return parse_ram(v)

    @field_validator("cpu", mode="before")
    @classmethod
    def parse_cpu_value(cls, v: int | str) -> int | str:
        return parse_int_or_var(v, minimum=1, field_name="cpu")


class Role(SDLModel):
    """A named role on a VM with optional entity assignments.

    Shorthand: ``admin: "username"`` (just the username string).
    Longhand: ``admin: {username: "admin", entities: ["blue-team.bob"]}``.
    """

    username: str
    entities: list[str] = Field(default_factory=list)


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

    confidentiality: AssetValueLevel | str = AssetValueLevel.MEDIUM
    integrity: AssetValueLevel | str = AssetValueLevel.MEDIUM
    availability: AssetValueLevel | str = AssetValueLevel.MEDIUM

    @field_validator(
        "confidentiality",
        "integrity",
        "availability",
        mode="before",
    )
    @classmethod
    def normalize_asset_value(
        cls,
        v: AssetValueLevel | str,
    ) -> AssetValueLevel | str:
        return parse_enum_or_var(
            v,
            AssetValueLevel,
            field_name="asset_value",
        )


class ServicePort(SDLModel):
    """A network service exposed by a node. From OCSF NetworkEndpoint."""

    port: int | str
    protocol: str = "tcp"
    name: str = ""
    description: str = ""

    @field_validator("port", mode="before")
    @classmethod
    def parse_port_value(cls, v: int | str) -> int | str:
        return parse_int_or_var(v, minimum=1, maximum=65535, field_name="port")


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
    os: Optional[OSFamily | str] = None
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
        return (
            parse_enum_or_var(v, OSFamily, field_name="os")
            if v is not None
            else v
        )

    @model_validator(mode="after")
    def validate_type_constraints(self) -> "Node":
        """Switch nodes cannot carry VM-only fields."""
        if self.type == NodeType.SWITCH:
            disallowed_fields: list[str] = []
            if self.source is not None:
                disallowed_fields.append("source")
            if self.resources is not None:
                disallowed_fields.append("resources")
            if self.os is not None:
                disallowed_fields.append("os")
            if self.os_version:
                disallowed_fields.append("os_version")
            if self.features:
                disallowed_fields.append("features")
            if self.conditions:
                disallowed_fields.append("conditions")
            if self.injects:
                disallowed_fields.append("injects")
            if self.vulnerabilities:
                disallowed_fields.append("vulnerabilities")
            if self.roles:
                disallowed_fields.append("roles")
            if self.services:
                disallowed_fields.append("services")
            if self.asset_value is not None:
                disallowed_fields.append("asset_value")
            if disallowed_fields:
                raise ValueError(
                    "Switch nodes cannot have VM-only fields: "
                    + ", ".join(disallowed_fields)
                )
        return self

    @model_validator(mode="after")
    def validate_unique_service_ports(self) -> "Node":
        """Concrete VM service bindings must stay uniquely addressable."""
        if self.type != NodeType.VM:
            return self

        seen: set[tuple[str, int]] = set()
        seen_names: set[str] = set()
        for service in self.services:
            if not isinstance(service.port, int):
                pass
            elif not is_variable_ref(service.protocol):
                key = (service.protocol.lower(), service.port)
                if key in seen:
                    raise ValueError(
                        "Duplicate service binding "
                        f"'{service.protocol}/{service.port}' on node"
                    )
                seen.add(key)
            if service.name:
                if service.name in seen_names:
                    raise ValueError(
                        f"Duplicate named service '{service.name}' on node"
                    )
                seen_names.add(service.name)
        return self
