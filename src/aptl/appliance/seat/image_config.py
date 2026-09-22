"""What a seat image declares about itself.

A seat image is self-describing: it states the resources its VM needs and
carries the appliance boundary policy its guest is launched under.  Both used
to come from a signed release manifest built alongside the disk; they now
travel with the image, so the thing that boots and the contract describing how
to boot it cannot drift apart.

The boundary policy is the existing platform model, validated by its own
rules, so loopback-only publication, the Docker authority and the containment
contract keep being enforced exactly as before.  This adds only the bounds
that matter for launching: an image asking for absurd resources, or one that
publishes nothing a participant can reach, is refused rather than launched.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aptl.core.appliance_boundary import ApplianceBoundaryPolicy, GuestPublication

SEAT_IMAGE_CONFIG_MEDIA_TYPE = "application/vnd.aptl.seat.config.v1+json"

# A seat is one workstation-class VM, not a cluster. These ceilings exist so a
# published image cannot ask a host for something unreasonable.
_MAX_VCPUS = 128
_MAX_MEMORY_BYTES = 1024 * 1024 * 1024 * 1024
_MAX_DISK_BYTES = 8 * 1024 * 1024 * 1024 * 1024
_SHA256 = r"^sha256:[a-f0-9]{64}$"
_IMAGE_DIGEST = r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$"


class SeatImageConfigError(ValueError):
    """One seat image declared a configuration that cannot be launched."""


class SeatImageResources(BaseModel):
    """The host resources one seat image needs to run."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    vcpus: int = Field(ge=1, le=_MAX_VCPUS)
    memory_bytes: int = Field(ge=512 * 1024 * 1024, le=_MAX_MEMORY_BYTES)
    disk_bytes: int = Field(ge=1024 * 1024 * 1024, le=_MAX_DISK_BYTES)


class SeatImageBinding(BaseModel):
    """Guest-side identities the boundary gate binds a launch to.

    Whoever bakes the image is the only party that knows which helper and
    proxy images it contains, so the image states them rather than a release
    manifest built beside it.  The gate keeps enforcing them unchanged.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    boundary_helper_image: str = Field(pattern=_IMAGE_DIGEST)
    egress_proxy_image: str = Field(pattern=_IMAGE_DIGEST)
    raes_plan_digest: str = Field(pattern=_SHA256)


class SeatImageConfig(BaseModel):
    """The complete self-description carried by one seat image."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.seat-image/v1"]
    resources: SeatImageResources
    boundary: ApplianceBoundaryPolicy
    binding: SeatImageBinding
    description: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def validate_publications(self) -> SeatImageConfig:
        # The seat exists to project the guest's endpoints to the host; an
        # image that publishes none cannot be reached and must not launch.
        audiences = [item.audience for item in self.boundary.guest_publications]
        if not audiences:
            raise ValueError("a seat image must publish at least one guest endpoint")
        if "participant" not in audiences:
            raise ValueError("a seat image must publish a participant endpoint")
        return self

    @property
    def publications(self) -> list[GuestPublication]:
        return self.boundary.guest_publications

    @property
    def participant(self) -> GuestPublication:
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
