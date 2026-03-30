"""SDL error types.

Provides structured error reporting for parsing and semantic validation.
SDLValidationError collects all issues from a validation pass rather
than failing on the first error.
"""

from pathlib import Path
from typing import Optional


class SDLError(Exception):
    """Base exception for all SDL operations."""


class SDLParseError(SDLError):
    """YAML parsing or structural validation failed.

    Attributes:
        path: The file that failed to parse (if applicable).
        details: Detailed error message.
    """

    def __init__(self, message: str, path: Optional[Path] = None) -> None:
        self.path = path
        self.details = message
        prefix = f"{path}: " if path else ""
        super().__init__(f"{prefix}{message}")


class SDLValidationError(SDLError):
    """Semantic validation failed.

    Collects all errors found during a validation pass rather than
    failing on the first one.

    Attributes:
        errors: List of individual error descriptions.
        path: The file that failed validation (if applicable).
    """

    def __init__(
        self, errors: list[str], path: Optional[Path] = None
    ) -> None:
        self.errors = errors
        self.path = path
        prefix = f"{path}: " if path else ""
        count = len(errors)
        summary = f"{count} validation error{'s' if count != 1 else ''}"
        detail = "\n  ".join(errors)
        super().__init__(f"{prefix}{summary}:\n  {detail}")
