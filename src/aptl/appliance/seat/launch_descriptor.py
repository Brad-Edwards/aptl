"""The create-once projection that carries a seat image into first boot.

The launcher writes this once per generation and mounts it read-only into the
guest.  It is the guest's statement of what it is: which image it came from,
which boundary policy it runs under, and which host observation admitted it.

A v1 descriptor projected a verified release directory.  A seat image is
self-describing instead, so v2 names the image and the digests that came with
it.  The create-once and digest-binding semantics are unchanged: the
descriptor is written once, never rewritten in place, and its digest is what
the seat record and the readiness challenge bind to.
"""

from __future__ import annotations

from typing import Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, Field

_SHA256 = r"^sha256:[a-f0-9]{64}$"
_IMAGE_DIGEST = r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$"


class SeatLaunchDescriptor(BaseModel):
    """Create-once projection that carries one seat image into first boot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.appliance-launch/v2"]
    image_reference: str = Field(min_length=1, max_length=512)
    image_digest: str = Field(pattern=_SHA256)
    image_config_digest: str = Field(pattern=_SHA256)
    boundary_policy_digest: str = Field(pattern=_SHA256)
    boundary_helper_image: str = Field(pattern=_IMAGE_DIGEST)
    egress_proxy_image: str = Field(pattern=_IMAGE_DIGEST)
    participant_routes_digest: str = Field(pattern=_SHA256)
    host_mcp_contract: Literal["aptl.restricted-ssh-mcp/v1"] | None = None
    host_observation_id: str = Field(min_length=1, max_length=128)


def canonical_launch_bytes(descriptor: SeatLaunchDescriptor) -> bytes:
    """Return deterministic RFC 8785 bytes for one launch projection."""

    return rfc8785.dumps(descriptor.model_dump(mode="json"))
