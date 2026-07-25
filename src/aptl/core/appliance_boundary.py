"""Strict platform-owned appliance boundary policy contracts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_AUTHORITY = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_LABEL_SELECTOR = re.compile(r"^[a-z0-9][a-z0-9._/-]*=[a-z0-9][a-z0-9._-]*$")

Digest = Annotated[str, Field(pattern=_DIGEST.pattern)]
PlatformZone = Literal["participant", "management", "egress"]
Transport = Literal["tcp", "udp"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PlatformAnchors(_StrictModel):
    participant: str
    management: str
    egress: str

    @field_validator("participant", "management", "egress")
    @classmethod
    def validate_label_selector(cls, value: str) -> str:
        if not _LABEL_SELECTOR.fullmatch(value):
            raise ValueError("platform anchors must be exact label selectors")
        return value


class FixedCrossing(_StrictModel):
    source: PlatformZone
    destination: PlatformZone
    protocol: Transport
    ports: list[int] = Field(min_length=1)
    purpose: str = Field(min_length=1, max_length=80)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if len(values) != len(set(values)) or any(
            isinstance(value, bool) or not 0 < value <= 65535 for value in values
        ):
            raise ValueError("ports must be unique integers in 1..65535")
        return values


class EgressAuthority(_StrictModel):
    authority: str
    port: int = Field(ge=1, le=65535)
    purpose: str = Field(min_length=1, max_length=80)

    @field_validator("authority")
    @classmethod
    def validate_authority(cls, value: str) -> str:
        normalized = value.rstrip(".").lower()
        try:
            ipaddress.ip_address(normalized.strip("[]"))
        except ValueError:
            pass
        else:
            raise ValueError("egress authority must not be an IP literal")
        if "*" in normalized or "://" in normalized or not _AUTHORITY.fullmatch(
            normalized
        ):
            raise ValueError("egress authority must be one exact DNS authority")
        return normalized


class GuestPublication(_StrictModel):
    audience: Literal["participant", "recovery"]
    address: str
    port: int = Field(ge=1, le=65535)
    protocol: Transport

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        parsed = ipaddress.ip_address(value)
        if not parsed.is_loopback:
            raise ValueError("guest publications must bind loopback")
        return str(parsed)


class DockerAuthorityPolicy(_StrictModel):
    allowed_holder_labels: list[str] = Field(default_factory=list)
    require_guest_daemon: Literal[True] = True

    @field_validator("allowed_holder_labels")
    @classmethod
    def validate_holder_labels(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(
            not _LABEL_SELECTOR.fullmatch(value) for value in values
        ):
            raise ValueError("Docker authority holders require unique exact labels")
        return values


class ApplianceBoundaryPolicy(_StrictModel):
    """Platform policy that deliberately cannot contain scenario topology."""

    schema_version: Literal["aptl.appliance-boundary/v1"]
    policy_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,79}$")
    generation: int = Field(ge=1)
    default_deny: Literal[True]
    platform_anchors: PlatformAnchors
    fixed_crossings: list[FixedCrossing] = Field(default_factory=list)
    egress_authorities: list[EgressAuthority] = Field(default_factory=list)
    guest_publications: list[GuestPublication] = Field(default_factory=list)
    docker_authority: DockerAuthorityPolicy

    @model_validator(mode="after")
    def validate_unique_entries(self) -> ApplianceBoundaryPolicy:
        crossings = [
            (item.source, item.destination, item.protocol, tuple(item.ports))
            for item in self.fixed_crossings
        ]
        authorities = [
            (item.authority, item.port) for item in self.egress_authorities
        ]
        publications = [
            (item.audience, item.address, item.port, item.protocol)
            for item in self.guest_publications
        ]
        if len(crossings) != len(set(crossings)):
            raise ValueError("fixed crossings must be unique")
        if len(authorities) != len(set(authorities)):
            raise ValueError("egress authorities must be unique")
        if len(publications) != len(set(publications)):
            raise ValueError("guest publications must be unique")
        return self


class ApplianceBoundaryBinding(_StrictModel):
    """Trusted projection supplied by the signed envelope and launcher."""

    policy_digest: Digest
    payload_digest: Digest
    aces_plan_digest: Digest
    boot_id: str = Field(min_length=1, max_length=128)
    guest_daemon_id: str = Field(min_length=1, max_length=128)
    host_observation_id: str = Field(min_length=1, max_length=128)


def load_boundary_policy(
    path: Path,
    binding: ApplianceBoundaryBinding,
) -> ApplianceBoundaryPolicy:
    """Load a strict policy whose exact bytes match the envelope projection."""

    payload = path.read_bytes()
    actual = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual != binding.policy_digest:
        raise ValueError("appliance boundary policy digest does not match binding")
    parsed = json.loads(payload)
    if not isinstance(parsed, dict):
        raise ValueError("appliance boundary policy must be a JSON object")
    return ApplianceBoundaryPolicy.model_validate(parsed)
