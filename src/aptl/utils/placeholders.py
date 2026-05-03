"""Detection of `.env.example`-shaped placeholder values.

Centralised so that every layer that consumes secret-shaped env vars
rejects the same set of placeholder markers in lockstep — without that,
adding a new marker (or fixing a missed substring) means tracking down
duplicate constant tuples scattered across the codebase.
"""

from __future__ import annotations

# Substrings that identify a `.env.example` placeholder rather than a
# real value. Checked case-insensitively. Add new markers here and they
# take effect everywhere that imports :func:`contains_placeholder` or
# :data:`PLACEHOLDER_MARKERS`.
PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "CHANGE_ME",
    "CHANGEME",
    "PLEASEREPLACEME",
    "REPLACE_ME",
)


def contains_placeholder(value: str | None) -> bool:
    """Return True if *value* contains any of :data:`PLACEHOLDER_MARKERS`.

    Empty / ``None`` values return ``False`` (no placeholder to flag).
    """
    if not value:
        return False
    upper = value.upper()
    return any(marker in upper for marker in PLACEHOLDER_MARKERS)
