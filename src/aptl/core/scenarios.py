"""Scenario loading helpers and shared exceptions for SDL specifications.

The SDL models live in ``aptl.core.sdl``. This module intentionally
provides only file loading, discovery, and exception types shared by
the current SDL-only surface.
"""

from pathlib import Path
from typing import Optional

from aptl.core.sdl import parse_sdl, Scenario, SDLParseError, SDLValidationError
from aptl.utils.logging import get_logger

log = get_logger("scenarios")


# ---------------------------------------------------------------------------
# Exceptions (used throughout the runtime)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Loading functions
# ---------------------------------------------------------------------------


def load_scenario(path: Path) -> Scenario:
    """Load and validate a scenario from a YAML file.

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

    log.info("Loaded scenario '%s' from %s", scenario.name, path)
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
