"""Bounded seat-launcher failure codes."""

from __future__ import annotations


class SeatLauncherError(RuntimeError):
    """A seat lifecycle operation failed with a stable operator-facing code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)
