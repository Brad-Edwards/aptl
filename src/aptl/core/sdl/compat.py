"""Backward compatibility layer for aptl.core.scenarios consumers.

Provides all names previously exported by ``aptl.core.scenarios``
so that existing imports continue to work unchanged. The old
``ScenarioDefinition`` becomes a type alias for ``Scenario``.
"""

import re
from pathlib import Path
from typing import Optional

import yaml

from aptl.core.sdl._errors import SDLParseError, SDLValidationError
from aptl.core.sdl.attacks import AttackStep, ExpectedDetection, MitreReference, SeverityId
from aptl.core.sdl.objectives import (
    CommandOutputValidation,
    FileExistsValidation,
    Hint,
    Objective,
    ObjectiveSet,
    ObjectiveType,
    ScoringConfig,
    TimeBonusConfig,
    WazuhAlertValidation,
)
from aptl.core.sdl.parser import parse_sdl
from aptl.core.sdl.scenario import (
    ContainerRequirements,
    Difficulty,
    Precondition,
    PreconditionType,
    Scenario,
    ScenarioMetadata,
    ScenarioMode,
)

from aptl.utils.logging import get_logger

log = get_logger("scenarios")

# --- Type alias ---
ScenarioDefinition = Scenario


# --- Exception aliases ---
class ScenarioError(Exception):
    """Base exception for all scenario operations."""


class ScenarioNotFoundError(ScenarioError):
    """A scenario file or ID could not be found."""

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        super().__init__(f"Scenario not found: {identifier}")


class ScenarioValidationError(ScenarioError):
    """A scenario definition failed validation."""

    def __init__(self, message: str, path: Optional[Path] = None) -> None:
        self.path = path
        self.details = message
        prefix = f"{path}: " if path else ""
        super().__init__(f"{prefix}{message}")


class ScenarioStateError(ScenarioError):
    """An invalid state transition was attempted."""


class ObserverError(ScenarioError):
    """The Wazuh observation bus encountered an error."""


# --- Config loading ---
def _get_config():
    """Lazily import AptlConfig to avoid circular imports."""
    from aptl.core.config import AptlConfig
    return AptlConfig


# --- Loading functions ---
_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def load_scenario(path: Path) -> Scenario:
    """Load and validate a scenario definition from a YAML file.

    Drop-in replacement for the original ``scenarios.load_scenario()``.
    Accepts both APTL legacy format and OCR SDL format.

    Args:
        path: Path to a .yaml scenario file.

    Returns:
        Validated Scenario.

    Raises:
        FileNotFoundError: If the file does not exist.
        ScenarioValidationError: If YAML is malformed or fails validation.
    """
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {path}")

    raw = path.read_text().strip()
    if not raw:
        raise ScenarioValidationError("Scenario file is empty", path=path)

    try:
        scenario = parse_sdl(raw, path=path)
    except SDLParseError as e:
        raise ScenarioValidationError(str(e), path=path) from e
    except SDLValidationError as e:
        raise ScenarioValidationError(str(e), path=path) from e

    scenario_id = (
        scenario.metadata.id if scenario.metadata else scenario.name
    )
    log.info("Loaded scenario '%s' from %s", scenario_id, path)
    return scenario


def find_scenarios(search_dir: Path) -> list[Path]:
    """Find all .yaml scenario files in a directory (non-recursive).

    Args:
        search_dir: Directory to search.

    Returns:
        Sorted list of paths to .yaml files.
    """
    if not search_dir.is_dir():
        log.debug("Scenarios directory does not exist: %s", search_dir)
        return []

    paths = sorted(search_dir.glob("*.yaml"))
    log.debug("Found %d scenario files in %s", len(paths), search_dir)
    return paths


def validate_scenario_containers(
    scenario: Scenario,
    config: object,
) -> list[str]:
    """Check that all containers required by a scenario are enabled.

    Args:
        scenario: The scenario to check.
        config: Current APTL configuration.

    Returns:
        List of required containers that are not enabled.
    """
    if scenario.containers is None:
        return []
    enabled = set(config.containers.enabled_profiles())
    required = set(scenario.containers.required)
    missing = sorted(required - enabled)
    if missing:
        scenario_id = (
            scenario.metadata.id if scenario.metadata else scenario.name
        )
        log.warning(
            "Scenario '%s' requires disabled containers: %s",
            scenario_id,
            ", ".join(missing),
        )
    return missing
