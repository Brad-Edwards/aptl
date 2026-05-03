"""Service configuration loaded from environment variables.

Pydantic v2 model populated via :meth:`ServiceConfig.from_env`. The project
does not use ``pydantic-settings``; this mirrors the env-then-validate pattern
used by ``aptl.api.deps``.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator


_DEFAULT_RULES_PATH = "/etc/suricata/rules/misp/misp-iocs.rules"
_DEFAULT_SOCKET_PATH = "/var/run/suricata/suricata-command.socket"
_MIN_INTERVAL_SECONDS = 30
_SID_BASE_MIN = 1_500_000
_SID_BASE_MAX = 2_999_999


def _bool_env(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class ServiceConfig(BaseModel):
    """Runtime configuration for the sync service."""

    model_config = ConfigDict(extra="forbid")

    misp_url: str
    misp_api_key: str
    misp_verify_ssl: bool
    ioc_tag_filter: str
    sync_interval_seconds: int
    rules_out_path: Path
    suricata_socket_path: Path
    sid_base: int
    log_level: str

    @field_validator("misp_api_key")
    @classmethod
    def _validate_api_key(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("MISP_API_KEY must be set")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _validate_interval(cls, v: int) -> int:
        if v < _MIN_INTERVAL_SECONDS:
            raise ValueError(
                f"SYNC_INTERVAL_SECONDS must be >= {_MIN_INTERVAL_SECONDS}"
            )
        return v

    @field_validator("sid_base")
    @classmethod
    def _validate_sid_base(cls, v: int) -> int:
        if not _SID_BASE_MIN <= v <= _SID_BASE_MAX:
            raise ValueError(
                f"SID_BASE must be in [{_SID_BASE_MIN}, {_SID_BASE_MAX}]"
            )
        return v

    @field_validator("ioc_tag_filter")
    @classmethod
    def _validate_tag_filter(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("IOC_TAG_FILTER must not be empty")
        return v

    @classmethod
    def from_env(cls) -> "ServiceConfig":
        api_key = os.environ.get("MISP_API_KEY")
        if api_key is None or not api_key.strip():
            raise ValueError("MISP_API_KEY environment variable is required")

        return cls(
            misp_url=os.environ.get("MISP_URL", "https://misp"),
            misp_api_key=api_key,
            misp_verify_ssl=_bool_env(os.environ.get("MISP_VERIFY_SSL"), False),
            ioc_tag_filter=os.environ.get("IOC_TAG_FILTER", "aptl:enforce"),
            sync_interval_seconds=int(
                os.environ.get("SYNC_INTERVAL_SECONDS", "300")
            ),
            rules_out_path=Path(
                os.environ.get("RULES_OUT_PATH", _DEFAULT_RULES_PATH)
            ),
            suricata_socket_path=Path(
                os.environ.get("SURICATA_SOCKET_PATH", _DEFAULT_SOCKET_PATH)
            ),
            sid_base=int(os.environ.get("SID_BASE", "2000000")),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        )
