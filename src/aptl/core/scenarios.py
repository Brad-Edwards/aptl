"""Shared scenario/session exception types.

APTL no longer exposes an in-tree scenario YAML loader. Public startup scenario
selection flows through ``aptl.core.scenario_catalog`` and the ACES parser.
This module stays as the compatibility home for exceptions used by session and
continuity code.
"""

from pathlib import Path


class ScenarioError(Exception):
    """Base exception for all scenario operations."""


class ScenarioNotFoundError(ScenarioError):
    """A scenario file or ID could not be found."""

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        super().__init__(f"Scenario not found: {identifier}")


class ScenarioValidationError(ScenarioError):
    """A scenario definition failed validation."""

    def __init__(self, message: str, path: Path | None = None) -> None:
        self.path = path
        self.details = message
        prefix = f"{path}: " if path else ""
        super().__init__(f"{prefix}{message}")


class ScenarioStateError(ScenarioError):
    """An invalid state transition was attempted."""


class ObserverError(ScenarioError):
    """The Wazuh observation bus encountered an error."""
