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
        profiles = []
        for field_name in [
            "wazuh", "victim", "kali", "reverse",
            "enterprise", "soc", "mail", "fileshare", "dns",
        ]:
            if getattr(self, field_name):
                profiles.append(field_name)
        return profiles


class AptlConfig(BaseModel):
    """Top-level APTL configuration."""

    model_config = ConfigDict(extra="ignore")

    lab: LabSettings = LabSettings(name="aptl")
    containers: ContainerSettings = ContainerSettings()


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
