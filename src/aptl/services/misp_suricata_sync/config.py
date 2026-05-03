"""Service configuration loaded from environment variables.

Pydantic v2 model populated via :meth:`ServiceConfig.from_env`. The project
does not use ``pydantic-settings``; this mirrors the env-then-validate pattern
used by ``aptl.api.deps``.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator


_DEFAULT_RULES_PATH = "/var/lib/suricata/rules/misp/misp-iocs.rules"
_DEFAULT_SOCKET_PATH = "/var/run/suricata/suricata-command.socket"
_MIN_INTERVAL_SECONDS = 30

# SID_BASE bounds + the 24-bit translator offset (16_777_216) must keep
# generated SIDs inside Suricata's 32-bit SID space (max 2**31-1 by
# convention) and clear of the bundled ET Open / local.rules ranges
# (~1M-3M). The default 99_000_000 + 0xFFFFFF lands at ~115_777_215,
# well above any standard ruleset.
_SID_OFFSET_MAX = 0xFFFFFF
_SID_BASE_MIN = 10_000_000
_SID_BASE_MAX = 2_000_000_000 - _SID_OFFSET_MAX
_DEFAULT_SID_BASE = 99_000_000

# Marker substrings that indicate the operator pasted a placeholder from
# `.env.example` instead of a real key. Rejected at startup so the lab
# fails loudly rather than running with a known-bogus credential.
_PLACEHOLDER_MARKERS = (
    "CHANGE_ME",
    "CHANGEME",
    "PLEASEREPLACEME",
    "REPLACE_ME",
)


_TRUE_TOKENS = frozenset({"1", "true", "yes", "on"})
_FALSE_TOKENS = frozenset({"0", "false", "no", "off"})


def _bool_env(value: str | None, default: bool) -> bool:
    """Strict boolean env-var parser.

    Unknown tokens (typos like ``ture``) raise ``ValueError`` rather than
    silently falling through to ``False`` — the silent path turned a
    harmless typo into a security regression once already
    (``MISP_VERIFY_SSL=ture`` would disable verification).
    """
    if value is None:
        return default
    token = value.strip().lower()
    if not token:
        return default
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    raise ValueError(
        f"Invalid boolean env value {value!r}; "
        f"expected one of {sorted(_TRUE_TOKENS | _FALSE_TOKENS)}"
    )


class ServiceConfig(BaseModel):
    """Runtime configuration for the sync service."""

    model_config = ConfigDict(extra="forbid")

    misp_url: str
    misp_api_key: str
    misp_verify_ssl: bool
    misp_ca_cert_path: Path | None
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
        upper = v.strip().upper()
        for marker in _PLACEHOLDER_MARKERS:
            if marker in upper:
                raise ValueError(
                    "MISP_API_KEY is a placeholder; replace it in .env "
                    "with a real value (see .env.example for instructions)"
                )
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

        ca_cert_raw = os.environ.get("MISP_CA_CERT_PATH", "").strip()
        ca_cert = Path(ca_cert_raw) if ca_cert_raw else None

        return cls(
            misp_url=os.environ.get("MISP_URL", "https://misp"),
            misp_api_key=api_key,
            misp_verify_ssl=_bool_env(os.environ.get("MISP_VERIFY_SSL"), False),
            misp_ca_cert_path=ca_cert,
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
            sid_base=int(os.environ.get("SID_BASE", str(_DEFAULT_SID_BASE))),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        )
