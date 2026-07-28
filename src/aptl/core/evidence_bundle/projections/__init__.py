"""Closed, versioned projection registry and the built-in projections.

Importing this package registers the built-in JSONL, Parquet, and OCSF-aligned
projections. Selection is by format name against this closed registry; there is
no dynamic import or plugin discovery.
"""

from __future__ import annotations

from aptl.core.evidence_bundle.projections import jsonl, ocsf, parquet  # noqa: F401
from aptl.core.evidence_bundle.projections.registry import (
    ProjectionContext,
    ProjectionResult,
    ProjectionRun,
    available_formats,
    get_projection,
    run_projections,
)

__all__ = [
    "ProjectionContext",
    "ProjectionResult",
    "ProjectionRun",
    "available_formats",
    "get_projection",
    "run_projections",
]
