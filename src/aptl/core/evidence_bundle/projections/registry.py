"""Closed, versioned projection registry for the evidence bundle.

Projections are optional, derived, loss-accounted views over the canonical
evidence records — selected by a closed export policy, never guessed. An unknown
format fails closed; a projection with nothing to project or a missing optional
dependency records a limitation rather than fabricating output (EXP-008
preflight "Projections are optional, derived, and loss-accounted").

Registrations are code-owned data, not a plugin loader: adding a format means
adding one pure mapping module here, not a dynamic import.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aptl.core.evidence_bundle.archive import BundleMember
from aptl.core.evidence_bundle.closure import ClosureLimitation
from aptl.core.evidence_bundle.envelope import ProjectionDescriptor
from aptl.core.evidence_bundle.errors import BundleError
from aptl.core.evidence_bundle.limits import BundleLimits


@dataclass(frozen=True)
class ProjectionContext:
    """Everything a projection may read.

    ``records`` are the parsed CANONICAL SOURCE dicts (not re-serialized pydantic
    models), so a projection preserves each field's exact source presence —
    absent vs explicit ``null`` stay distinguishable, which the round-trip
    contract makes load-bearing.
    """

    run_dir: Path
    records: tuple[dict, ...]
    retained_sizes: Mapping[str, int | None]
    limits: BundleLimits


@dataclass(frozen=True)
class ProjectionResult:
    """One projection's output: a descriptor, its members, and any limitations."""

    descriptor: ProjectionDescriptor | None
    members: tuple[BundleMember, ...]
    limitations: tuple[ClosureLimitation, ...]


class Projection(Protocol):
    format: str

    def project(self, ctx: ProjectionContext) -> ProjectionResult: ...


@dataclass(frozen=True)
class ProjectionRun:
    """Aggregated output across every requested projection."""

    members: tuple[BundleMember, ...]
    descriptors: tuple[ProjectionDescriptor, ...]
    limitations: tuple[ClosureLimitation, ...]


_REGISTRY: dict[str, Projection] = {}


def register(projection: Projection) -> None:
    _REGISTRY[projection.format] = projection


def available_formats() -> frozenset[str]:
    return frozenset(_REGISTRY)


def get_projection(fmt: str) -> Projection:
    try:
        return _REGISTRY[fmt]
    except KeyError as exc:
        raise BundleError(
            "unknown_projection_format",
            f"unknown projection format {fmt!r}; known: {sorted(_REGISTRY)}",
        ) from exc


def run_projections(formats: Sequence[str], ctx: ProjectionContext) -> ProjectionRun:
    """Run each requested projection (deduped, ordered) and aggregate output."""
    members: list[BundleMember] = []
    descriptors: list[ProjectionDescriptor] = []
    limitations: list[ClosureLimitation] = []
    for fmt in sorted(set(formats)):
        result = get_projection(fmt).project(ctx)
        members.extend(result.members)
        if result.descriptor is not None:
            descriptors.append(result.descriptor)
        limitations.extend(result.limitations)
    return ProjectionRun(
        members=tuple(members),
        descriptors=tuple(descriptors),
        limitations=tuple(limitations),
    )


__all__ = [
    "ProjectionContext",
    "ProjectionResult",
    "Projection",
    "ProjectionRun",
    "register",
    "available_formats",
    "get_projection",
    "run_projections",
]
