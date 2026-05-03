"""Shared lab lifecycle data classes.

Lives in a leaf module so deployment backends (which are imported
during ``aptl.core.lab`` module load) can reference these types
without importing the full ``aptl.core.lab`` module — that direction
created a circular import (``lab.py`` -> snapshot -> deployment
package -> backend.py / docker_compose.py -> ``aptl.core.lab``
mid-load).

``aptl.core.lab`` re-exports both names for backward compatibility,
so callers that already import from ``aptl.core.lab`` keep working.
"""

from dataclasses import dataclass, field


@dataclass
class LabResult:
    """Result of a lab lifecycle operation."""

    success: bool
    message: str = ""
    error: str = ""


@dataclass
class LabStatus:
    """Current status of the lab environment."""

    running: bool
    containers: list[dict] = field(default_factory=list)
    error: str = ""
