"""Value objects for the verified closure: entries, disclosures, and seal state.

Kept in their own module so both the closure assembly (:mod:`closure`) and the
reference-driven collectors (:mod:`_collect`) can import them without a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SealScope(str, Enum):
    """Whether the closure carries a verified #444 seal."""

    UNSEALED = "unsealed"
    VERIFIED = "verified"


@dataclass(frozen=True)
class ClosureLimitation:
    """A stable, disclosed reason a bundle is incomplete for a declared purpose."""

    code: str
    detail: str
    subject: str | None = None


@dataclass(frozen=True)
class Disclosures:
    """Sensitivity/visibility/redaction/loss carried from the owning record."""

    sensitivity: str | None = None
    visibility: str | None = None
    redaction_state: str | None = None
    loss_disclosure: str | None = None
    transformation: str | None = None


EMPTY_DISCLOSURES = Disclosures()


@dataclass(frozen=True)
class ClosureEntry:
    """One source artifact reachable from the closure roots."""

    bundle_path: str
    logical_role: str
    # canonical | backend-evidence | derived | reference
    classification: str
    contract_id: str | None
    source_ref: str
    # sha256:<hex> of the retained bytes
    digest: str
    size: int
    media_type: str
    source_run_relpath: str
    disclosures: Disclosures = EMPTY_DISCLOSURES
    provenance_ref: str | None = None
    clock_ref: str | None = None
    limitations: tuple[ClosureLimitation, ...] = ()


@dataclass(frozen=True)
class SealBinding:
    """The result of the #444 seal seam for one run."""

    scope: SealScope
    root_identity: str | None
    verifier_id: str | None
    limitations: tuple[ClosureLimitation, ...] = ()


@dataclass(frozen=True)
class VerifiedClosure:
    """The exact source closure the bundle packages, plus its seal + limitations."""

    run_id: str
    seal: SealBinding
    entries: tuple[ClosureEntry, ...]
    limitations: tuple[ClosureLimitation, ...]


__all__ = [
    "SealScope",
    "ClosureLimitation",
    "Disclosures",
    "EMPTY_DISCLOSURES",
    "ClosureEntry",
    "SealBinding",
    "VerifiedClosure",
]
