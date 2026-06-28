"""APTL configuration models and loading.

Uses Pydantic v2 for validation. Config is loaded from aptl.json files.
"""

import json
import re
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, field_validator, ConfigDict

from aptl.utils.logging import get_logger

log = get_logger("config")

_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
_CONFIG_FILENAMES = ["aptl.json"]


class LabSettings(BaseModel):
    """Lab-level configuration."""

    model_config = ConfigDict(extra="forbid")

    name: str
    network_subnet: str = "172.20.0.0/16"

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Lab name must not be empty")
        if not _NAME_PATTERN.match(v):
            raise ValueError(
                f"Lab name '{v}' is invalid. "
                "Use only alphanumeric characters, dots, hyphens, and underscores. "
                "Must start with an alphanumeric character."
            )
        return v


class ContainerSettings(BaseModel):
    """Which containers are enabled in the lab."""

    model_config = ConfigDict(extra="forbid")

    wazuh: bool = True
    victim: bool = True
    kali: bool = True
    reverse: bool = False
    enterprise: bool = False
    soc: bool = False
    mail: bool = False
    fileshare: bool = False
    dns: bool = False

    def enabled_profiles(self) -> list[str]:
        """Return docker compose profile names for enabled containers."""
        return [
            name for name in type(self).model_fields
            if getattr(self, name)
        ]


class RunStorageConfig(BaseModel):
    """Configuration for experiment run storage."""

    model_config = ConfigDict(extra="forbid")

    # "local" or "s3" (s3 deferred)
    backend: str = "local"
    # Relative to project dir
    local_path: str = "./runs"
    # Future
    s3_bucket: str | None = None
    # Future
    s3_prefix: str = "runs/"


class DeploymentConfig(BaseModel):
    """Configuration for deployment backend selection.

    Controls which deployment backend is used for lab lifecycle
    operations (start, stop, status, kill).  Defaults to local
    Docker Compose.
    """

    model_config = ConfigDict(extra="forbid")

    # "docker-compose" or "ssh-compose"
    provider: str = "docker-compose"
    project_name: str = "aptl"

    # SSH-specific fields (only used when provider == "ssh-compose")
    ssh_host: str | None = None
    ssh_user: str | None = None
    ssh_key: str | None = None
    ssh_port: int = 22
    remote_dir: str | None = None

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        allowed = {"docker-compose", "ssh-compose"}
        if v not in allowed:
            raise ValueError(
                f"Unknown deployment provider '{v}'. "
                f"Supported: {', '.join(sorted(allowed))}"
            )
        return v


_TIME_PATTERN = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class LifecycleScheduleEntry(BaseModel):
    """One scheduled-provisioning window (DEP-003).

    ``at`` is a 24-hour ``HH:MM`` wall-clock time interpreted in **UTC**
    (the platform stamps lifecycle timestamps as timezone-aware UTC, so
    the schedule shares that frame). ``days`` is an optional weekday
    filter (empty means every day). ``scenario`` optionally names a
    curated ACES startup scenario id to boot with.
    """

    model_config = ConfigDict(extra="forbid")

    at: str
    days: list[str] = []
    scenario: str | None = None

    @field_validator("at")
    @classmethod
    def validate_at(cls, v: str) -> str:
        if not _TIME_PATTERN.match(v):
            raise ValueError(
                f"Schedule 'at' must be a 24-hour HH:MM UTC time, got '{v}'."
            )
        return v

    @field_validator("days")
    @classmethod
    def validate_days(cls, v: list[str]) -> list[str]:
        normalized: list[str] = []
        for day in v:
            lowered = day.lower()
            if lowered not in _WEEKDAYS:
                raise ValueError(
                    f"Invalid weekday '{day}'. Use any of: {', '.join(_WEEKDAYS)}."
                )
            normalized.append(lowered)
        return normalized


class LabLifecyclePolicyConfig(BaseModel):
    """Ephemeral lifecycle policy for the range (DEP-003).

    Declarative policy consumed by ``aptl lab enforce`` / ``monitor`` to
    auto-teardown an idle or expired range and to provision on a
    schedule. Enforcement is a separate single-owner control-plane tick;
    this model is just the strict, first-party policy shape (ADR-025).
    All durations are bounded positive integers in minutes.
    """

    model_config = ConfigDict(extra="forbid")

    ttl_minutes: int | None = None
    idle_timeout_minutes: int | None = None
    teardown_remove_volumes: bool = True
    schedule: list[LifecycleScheduleEntry] = []

    @field_validator("ttl_minutes", "idle_timeout_minutes")
    @classmethod
    def validate_positive_minutes(cls, v: int | None) -> int | None:
        if v is not None and v <= 0:
            raise ValueError("must be a positive number of minutes")
        return v


class AptlConfig(BaseModel):
    """Top-level APTL configuration.

    `extra="forbid"` matches every nested model and enforces ADR-025:
    `aptl.json` is a strict first-party schema at every level, so
    unknown top-level keys (typos, dead sections) are validation
    errors rather than silent drift.
    """

    model_config = ConfigDict(extra="forbid")

    lab: LabSettings = LabSettings(name="aptl")
    containers: ContainerSettings = ContainerSettings()
    deployment: DeploymentConfig = DeploymentConfig()
    run_storage: RunStorageConfig = RunStorageConfig()
    lifecycle_policy: LabLifecyclePolicyConfig | None = None


def load_config(path: Path) -> AptlConfig:
    """Load and validate an APTL configuration file.

    Args:
        path: Path to a JSON config file.

    Returns:
        Validated AptlConfig instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the file contains invalid JSON or fails validation.
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = path.read_text().strip()
    if not raw:
        raise ValueError(f"Config file is empty: {path}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e

    # `AptlConfig(**data)` raises TypeError when `data` is a non-mapping
    # JSON top-level (int, float, str, bool, null, list). Classify that
    # into the documented `ValueError` contract so callers doing
    # `except (FileNotFoundError, ValueError)` see a consistent shape.
    if not isinstance(data, dict):
        raise ValueError(
            f"Config root must be a JSON object, got "
            f"{type(data).__name__}: {path}"
        )

    log.debug("Loaded config from %s", path)
    return AptlConfig(**data)


def find_config(search_dir: Path) -> Optional[Path]:
    """Search for an APTL config file in the given directory.

    Args:
        search_dir: Directory to search in.

    Returns:
        Path to the config file, or None if not found.
    """
    for filename in _CONFIG_FILENAMES:
        candidate = search_dir / filename
        if candidate.is_file():
            log.debug("Found config at %s", candidate)
            return candidate
    return None
