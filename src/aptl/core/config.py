"""APTL configuration models and loading.

Uses Pydantic v2 for validation. Config is loaded from aptl.json files.
"""

import json
import re
from pathlib import Path, PurePosixPath
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from aptl.utils.logging import get_logger

log = get_logger("config")

_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
_PARTICIPANT_MODEL_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$")
_IMMUTABLE_PARTICIPANT_MODEL_PATTERNS = {
    "claude": re.compile(r"^claude-[a-z0-9-]+-\d{8}$", flags=re.ASCII),
    "codex": re.compile(
        r"^(?:codex-[a-z0-9._-]+|gpt-[a-z0-9._-]+|o\d[a-z0-9._-]*)"
        r"-\d{4}-\d{2}-\d{2}$",
        flags=re.ASCII,
    ),
}
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

    # Defaults match the full TechVault env-pack scenario that
    # `aptl lab start` provisions when no scenario is given, so a plain
    # `aptl lab init` + `aptl lab start` brings up the complete lab the
    # walkthrough documents. With soc/enterprise/dns/fileshare off, Compose only
    # created the wazuh/victim/kali subset while the RAES handoff still tried to
    # wire the scenario's ad/dns/cortex/db nodes, so start failed with
    # "No such container". `reverse` and `mail` stay off — they are not part of
    # that scenario.
    wazuh: bool = True
    victim: bool = True
    kali: bool = True
    reverse: bool = False
    enterprise: bool = True
    soc: bool = True
    mail: bool = False
    fileshare: bool = True
    dns: bool = True

    def enabled_profiles(self) -> list[str]:
        """Return docker compose profile names for enabled containers."""
        return [name for name in type(self).model_fields if getattr(self, name)]


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


class ScenarioSourceConfig(BaseModel):
    """Which scenario APTL realizes, and where its bytes come from.

    A backend is handed a scenario; it does not own one. Selecting it is an
    operator decision made before ``aptl lab start`` rather than something the
    backend decides or switches at runtime, so it lives here.

    ``root`` is where the scenario's own inputs — its start-state document and
    the content it declares — are anchored. ``None`` keeps the historical
    behaviour of resolving them inside the APTL checkout. A configured root is
    operator input and is treated as untrusted: it must be a relative path that
    cannot escape the project.
    """

    model_config = ConfigDict(extra="forbid")

    identity: str = "techvault"
    root: str | None = None
    # ``env-pack`` (the default since #875) resolves the scenario from the
    # bundled ``raes-env-packs`` pack named by ``identity``, staged and validated
    # before use, with no host paths in the document. ``project-tree`` is the
    # legacy path that resolves it from the APTL checkout and requires an explicit
    # scenario. The operator selects the source; the backend never switches it.
    source: Literal["project-tree", "env-pack"] = "env-pack"

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        """Refuse an identity that names nothing."""

        cleaned = value.strip()
        if not cleaned:
            raise ValueError("scenario identity must not be empty")
        return cleaned

    @field_validator("root")
    @classmethod
    def validate_root(cls, value: str | None) -> str | None:
        """Refuse a root that is absolute, escapes upward, or carries a NUL."""

        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("scenario root must not be empty")
        if "\x00" in cleaned:
            raise ValueError("scenario root must not contain a NUL byte")
        candidate = PurePosixPath(cleaned)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(
                "scenario root must be a relative path contained by the project"
            )
        return cleaned


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
    curated RAES startup scenario id to boot with.
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


def validate_installed_participant_model_id(provider: str, value: str) -> str:
    """Validate one explicit, non-secret installed-provider model identity."""

    immutable_pattern = _IMMUTABLE_PARTICIPANT_MODEL_PATTERNS.get(provider)
    if (
        immutable_pattern is None
        or not isinstance(value, str)
        or not _PARTICIPANT_MODEL_PATTERN.fullmatch(value)
        or not immutable_pattern.fullmatch(value)
    ):
        raise ValueError("installed participant model identifier is invalid")
    return value


class InstalledParticipantModels(BaseModel):
    """Closed model selections for APTL's installed participant providers."""

    model_config = ConfigDict(extra="forbid")

    claude: str | None = Field(default=None, strict=True, max_length=128)
    codex: str | None = Field(default=None, strict=True, max_length=128)

    @field_validator("claude", "codex")
    @classmethod
    def validate_model(cls, value: str | None, info: ValidationInfo) -> str | None:
        """Reject implicit, ambiguous, or unsafe provider model identities."""

        if value is None:
            return None
        assert info.field_name is not None
        return validate_installed_participant_model_id(info.field_name, value)

    def model_for(self, provider: str) -> str:
        """Return one configured model or fail closed for installed use."""

        if provider not in {"claude", "codex"}:
            raise ValueError("unknown installed participant provider")
        model = getattr(self, provider)
        if model is None:
            raise ValueError(
                f"installed participant model is not configured for {provider}"
            )
        return model


class ExperimentSettings(BaseModel):
    """Strict non-secret apparatus settings approved for experiment binding."""

    model_config = ConfigDict(extra="forbid")

    participant_action_timeout_seconds: int = Field(
        default=120,
        strict=True,
        ge=1,
        le=3600,
    )
    participant_models: InstalledParticipantModels = Field(
        default_factory=InstalledParticipantModels
    )


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
    scenario: ScenarioSourceConfig = ScenarioSourceConfig()
    run_storage: RunStorageConfig = RunStorageConfig()
    lifecycle_policy: LabLifecyclePolicyConfig | None = None
    experiment: ExperimentSettings = ExperimentSettings()


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
            f"Config root must be a JSON object, got {type(data).__name__}: {path}"
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
