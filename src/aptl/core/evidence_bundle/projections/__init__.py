"""Closed, versioned projection registry and the built-in projections.

Importing this package registers the built-in JSONL, Parquet, and OCSF-aligned
projections. Selection is by format name against this closed registry; there is
no dynamic import or plugin discovery.
"""

from __future__ import annotations

from aptl.core.evidence_bundle.projections import jsonl, ocsf, parquet
from aptl.core.evidence_bundle.projections.registry import (
    ProjectionContext,
    ProjectionResult,
    ProjectionRun,
    available_formats,
    get_projection,
    run_projections,
)

# Importing the modules above runs their registration side effects; bind them to
# a name so the imports read as used and need no lint suppression.
_REGISTERED = (jsonl, ocsf, parquet)

__all__ = [
    "ProjectionContext",
    "ProjectionResult",
    "ProjectionRun",
    "available_formats",
    "get_projection",
    "run_projections",
]
