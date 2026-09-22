"""Versioned host seat contract persisted across reboot."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aptl.core.appliance_boundary_inventory import BoundaryEndpoint

SeatLifecycleState = Literal[
    "empty",
    "staged",
    "starting",
    "ready",
    "needs-reset",
    "recoverable-failure",
    "tainted",
]
SeatTaintState = Literal["clean", "tainted"]


class SeatRecord(BaseModel):
    """Outer seat metadata; not a second launch descriptor or aptl.json extension."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.seat-record/v1", "aptl.seat-record/v2"]
    seat_id: str = Field(min_length=1, max_length=64)
    instance_id: str = Field(default="legacy-instance", min_length=1, max_length=128)
    generation: int = Field(default=1, ge=1)
    image_reference: str = Field(min_length=1, max_length=512)
    image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    launch_descriptor_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    overlay_path: str = Field(min_length=1, max_length=160)
    host_observation_id: str = Field(min_length=1, max_length=128)
    lifecycle_state: SeatLifecycleState
    taint_state: SeatTaintState = "clean"
    host_boot_id: str = Field(min_length=1, max_length=128)
    mappings: tuple[BoundaryEndpoint, ...] = ()

    @field_validator("overlay_path")
    @classmethod
    def validate_overlay_path(cls, value: str) -> str:
        if value.startswith("/") or ".." in value.split("/"):
            raise ValueError("overlay path must be relative and contained")
        return value

    @model_validator(mode="after")
    def validate_mapping_set(self) -> "SeatRecord":
        """Require complete, unique outer endpoints in the v2 contract."""

        outer = [(item.address, item.port, item.protocol) for item in self.mappings]
        if len(outer) != len(set(outer)):
            raise ValueError("seat mappings require unique outer endpoints")
        if self.schema_version == "aptl.seat-record/v2" and (
            not self.mappings
            or any(
                item.guest_address is None or item.guest_port is None
                for item in self.mappings
            )
        ):
            raise ValueError("v2 seat records require complete guest mappings")
        return self


class SeatStatusProjection(BaseModel):
    """Coarse instructor-facing seat health without credentials or topology."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.seat-status/v1"] = "aptl.seat-status/v1"
    seat_id: str
    lifecycle_state: SeatLifecycleState
    taint_state: SeatTaintState
    image_reference: str
    image_digest: str
    launch_descriptor_digest: str
    host_observation_id: str
    diagnostics: tuple[str, ...] = ()
