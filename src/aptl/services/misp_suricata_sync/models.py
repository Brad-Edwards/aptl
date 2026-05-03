"""Data models for the MISP-to-Suricata sync service."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator


class MispAttribute(BaseModel):
    """A single IOC attribute pulled from MISP."""

    model_config = ConfigDict(extra="ignore")

    type: str
    value: str
    event_id: str | None = None

    @field_validator("type", "value")
    @classmethod
    def _reject_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v


class RenderedRule(BaseModel):
    """A rendered Suricata rule produced from one MISP attribute."""

    model_config = ConfigDict(extra="forbid")

    sid: int
    attribute_type: str
    attribute_value: str
    text: str
