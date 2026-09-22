"""What a seat image declares about itself.

A seat image is self-describing: it states the resources its VM needs and the
loopback endpoints its guest publishes.  That information used to come from a
signed release manifest built alongside the disk; it now travels with the
image as a small config blob, so the thing that boots and the thing that says
how to boot it cannot drift apart.

The declaration is bounded and strict.  An image that asks for absurd
resources, publishes a non-loopback address, or declares two endpoints for the
same audience is refused rather than launched.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SEAT_IMAGE_CONFIG_MEDIA_TYPE = "application/vnd.aptl.seat.config.v1+json"

# A seat is one workstation-class VM, not a cluster. These ceilings exist so a
# published image cannot ask a host for something unreasonable.
_MAX_VCPUS = 128
_MAX_MEMORY_BYTES = 1024 * 1024 * 1024 * 1024
_MAX_DISK_BYTES = 8 * 1024 * 1024 * 1024 * 1024


class SeatImageConfigError(ValueError):
    """One seat image declared a configuration that cannot be launched."""


class SeatImageResources(BaseModel):
    """The host resources one seat image needs to run."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    vcpus: int = Field(ge=1, le=_MAX_VCPUS)
    memory_bytes: int = Field(ge=512 * 1024 * 1024, le=_MAX_MEMORY_BYTES)
    disk_bytes: int = Field(ge=1024 * 1024 * 1024, le=_MAX_DISK_BYTES)


class SeatImagePublication(BaseModel):
    """One loopback guest endpoint the image expects to be projected."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    audience: Literal["participant", "recovery", "host-mcp"]
    protocol: Literal["tcp"]
    address: str
    port: int = Field(ge=1, le=65535)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        parsed = ipaddress.ip_address(value)
        if not parsed.is_loopback:
            raise ValueError("guest publications must bind loopback")
        return str(parsed)


class SeatImageConfig(BaseModel):
    """The complete self-description carried by one seat image."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.seat-image/v1"]
    resources: SeatImageResources
    publications: list[SeatImagePublication] = Field(min_length=1)
    description: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def validate_publications(self) -> SeatImageConfig:
        audiences = [item.audience for item in self.publications]
        if len(audiences) != len(set(audiences)):
            raise ValueError("each audience may be published exactly once")
        if "participant" not in audiences:
            raise ValueError("a seat image must publish a participant endpoint")
        return self

    @property
    def participant(self) -> SeatImagePublication:
        return next(
            item for item in self.publications if item.audience == "participant"
        )


def parse_seat_image_config(payload: bytes) -> SeatImageConfig:
    """Parse and validate one seat image config blob, fail-closed."""

    try:
        document = json.loads(payload)
    except ValueError as exc:
        raise SeatImageConfigError("seat image config is not valid JSON") from exc
    if not isinstance(document, dict):
        raise SeatImageConfigError("seat image config is not a JSON object")
    try:
        return SeatImageConfig.model_validate(document)
    except ValueError as exc:
        raise SeatImageConfigError(f"seat image config is invalid: {exc}") from exc
