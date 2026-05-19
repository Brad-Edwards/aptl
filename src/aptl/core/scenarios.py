"""Shared scenario exception types.

Active surface for now is exception classes consumed by the session
state machine + continuity CLI. The legacy in-tree SDL loader was
removed in #310 as part of the ACES SDL adoption; scenario authoring
moves to ACES (`aces_sdl.parse_sdl_file` + `aces_processor.RuntimeManager`).
"""

from pathlib import Path
from typing import Optional


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
