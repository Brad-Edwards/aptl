"""Versioned host seat contract persisted across reboot."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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

    schema_version: Literal["aptl.seat-record/v1"]
    seat_id: str = Field(min_length=1, max_length=64)
    selected_release_id: str = Field(min_length=1, max_length=128)
    launch_descriptor_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    overlay_path: str = Field(min_length=1, max_length=160)
    host_observation_id: str = Field(min_length=1, max_length=128)
    lifecycle_state: SeatLifecycleState
    taint_state: SeatTaintState = "clean"
    host_boot_id: str = Field(min_length=1, max_length=128)

    @field_validator("overlay_path")
    @classmethod
    def validate_overlay_path(cls, value: str) -> str:
        if value.startswith("/") or ".." in value.split("/"):
            raise ValueError("overlay path must be relative and contained")
        return value


class SeatStatusProjection(BaseModel):
    """Coarse instructor-facing seat health without credentials or topology."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["aptl.seat-status/v1"] = "aptl.seat-status/v1"
    seat_id: str
    lifecycle_state: SeatLifecycleState
    taint_state: SeatTaintState
    selected_release_id: str
    launch_descriptor_digest: str
    host_observation_id: str
    diagnostics: tuple[str, ...] = ()
