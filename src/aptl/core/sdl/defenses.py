"""Defense configuration models.

Provides structured representation for defense configurations
in scenarios. Currently a flexible dict-based model matching
the existing APTL ``defenses`` field; structured subtypes can
be added as the defense modeling matures.
"""

from typing import Any, Optional

from aptl.core.sdl._base import SDLModel


class DefenseConfig(SDLModel):
    """Defense configuration for a scenario.

    Wraps the free-form defense specification used in APTL
    scenarios (e.g., automated defenses, detection-only rules,
    absent controls).
    """

    automated: list[dict[str, Any]] = []
    detection_only: list[dict[str, Any]] = []
    absent: list[dict[str, Any]] = []
