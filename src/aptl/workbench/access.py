"""Private seat discovery and independent, management-issued MCP grants."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aptl.appliance.seat.models import SeatLifecycleState
from aptl.core.config import validate_compose_project_name
from aptl.core.scenario_bundle import PackIdentity
from aptl.workbench.profiles import (
    ServerProfile,
    WorkbenchConfigurationError,
    profile_for,
)

Identifier = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
Fingerprint = Annotated[str, Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")]


class _PrivateRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SeatEndpoint(_PrivateRecord):
    """An endpoint in one namespace; guest and outer ports are independent."""

    address: str
    port: int = Field(strict=True, ge=1, le=65535)

    @field_validator("address")
    @classmethod
    def loopback_only(cls, value: str) -> str:
        address = ipaddress.ip_address(value)
        if not address.is_loopback:
            raise ValueError("seat endpoint must bind loopback")
        return str(address)


class SeatAccessRecord(_PrivateRecord):
    """Secret-free discovery, never an authorization credential."""

    schema_version: Literal["aptl.seat-access/v1"]
    owner_id: Identifier
    seat_id: Identifier
    instance_id: Identifier
    generation: int = Field(strict=True, ge=1)
    guest_boot_id: Identifier
    guest_daemon_id: str = Field(min_length=1, max_length=128)
    guest_project: str
    container_ids: dict[str, str] = Field(min_length=1)
    scenario_pack: PackIdentity
    guest_endpoint: SeatEndpoint
    outer_endpoint: SeatEndpoint
    host_key_fingerprint: Fingerprint
    observed_at: datetime
    lifecycle_state: SeatLifecycleState

    @field_validator("guest_project")
    @classmethod
    def project_name(cls, value: str) -> str:
        return validate_compose_project_name(value)

    @field_validator("container_ids")
    @classmethod
    def native_ids(cls, values: dict[str, str]) -> dict[str, str]:
        if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in values.values()):
            raise ValueError("full native container IDs are required")
        if len(set(values.values())) != len(values):
            raise ValueError("container IDs must be unique")
        return values

    @field_validator("observed_at")
    @classmethod
    def utc_observation(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset().total_seconds() != 0:
            raise ValueError("observation must carry UTC timezone")
        return value


class CallerGrant(_PrivateRecord):
    """An independently enrolled key selects one role for one generation."""

    schema_version: Literal["aptl.mcp-grant/v1"]
    grant_id: Identifier
    owner_id: Identifier
    seat_id: Identifier
    instance_id: Identifier
    generation: int = Field(strict=True, ge=1)
    public_key_fingerprint: Fingerprint
    profile: Literal["red", "blue"]
    expires_at: datetime
    revoked: bool = Field(strict=True)

    @field_validator("expires_at")
    @classmethod
    def aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("grant expiry requires timezone")
        return value


def require_current_access(
    record: SeatAccessRecord,
    *,
    owner_id: str,
    seat_id: str,
    now: datetime | None = None,
) -> None:
    """Reject discovery which cannot identify a current ready seat."""
    age = ((now or datetime.now(UTC)) - record.observed_at).total_seconds()
    if (
        record.owner_id != owner_id
        or record.seat_id != seat_id
        or record.lifecycle_state != "ready"
        or not 0 <= age <= 120
    ):
        raise WorkbenchConfigurationError("seat access record is not current")


def authorize_server(
    record: SeatAccessRecord,
    grant: CallerGrant,
    server_id: str,
    *,
    now: datetime | None = None,
) -> ServerProfile:
    """Authorize before process creation or dispatch, not merely tools/list."""
    current = now or datetime.now(UTC)
    require_current_access(
        record, owner_id=record.owner_id, seat_id=record.seat_id, now=current
    )
    identity = ("owner_id", "seat_id", "instance_id", "generation")
    if (
        grant.revoked
        or grant.expires_at <= current
        or any(getattr(record, field) != getattr(grant, field) for field in identity)
    ):
        raise WorkbenchConfigurationError("MCP caller is not authorized")
    for server in profile_for(grant.profile).servers:
        if server.server_id == server_id:
            return server
    raise WorkbenchConfigurationError("MCP server is not authorized")
