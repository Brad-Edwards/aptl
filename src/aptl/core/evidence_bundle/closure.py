"""Verified-closure assembly for the EXP-008 evidence bundle.

The closure is the set of exact source bytes the bundle packages, assembled by
REFERENCE (see :mod:`aptl.core.evidence_bundle._collect`), never by scanning the
run directory (preflight: "Export one verified closure, never an ambient run
directory").

The seal is a seam. Until issue #444 produces a verified seal/root, the default
:class:`UnsealedClosureVerifier` reports ``SealScope.UNSEALED`` with an explicit
``seal-absent`` limitation. A ``ready-to-seal`` provenance state, a
``SEALED_READY`` disposition, a ``manifest.json``, or a ``checksums.sha256`` file
is NEVER treated as a verified seal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aptl.core.evidence_bundle import codes
from aptl.core.evidence_bundle._collect import (
    coalesce,
    collect_backend_evidence,
    collect_evidence,
)
from aptl.core.evidence_bundle.limits import DEFAULT_LIMITS, BundleLimits
from aptl.core.evidence_bundle.models import (
    ClosureEntry,
    ClosureLimitation,
    Disclosures,
    SealBinding,
    SealScope,
    VerifiedClosure,
)


class SealVerifier(Protocol):
    """The #444 seam: verify (or honestly decline to verify) a run's seal.

    A future sealed verifier receives run context out of band; the seam takes
    only ``run_id`` because the unsealed default needs nothing more.
    """

    def verify(self, run_id: str) -> SealBinding: ...


@dataclass(frozen=True)
class UnsealedClosureVerifier:
    """Default seam until #444 lands: report the closure as unsealed."""

    @staticmethod
    def verify(run_id: str) -> SealBinding:
        return SealBinding(
            scope=SealScope.UNSEALED,
            root_identity=None,
            verifier_id=None,
            limitations=(
                ClosureLimitation(
                    codes.SEAL_ABSENT,
                    "no #444 verified seal is available; bundle exported unsealed",
                    run_id,
                ),
            ),
        )


class ClosureSource(Protocol):
    """Enumerate the closure entries for one run (the pre-seal source seam)."""

    def collect(
        self, run_dir: Path, run_id: str, *, limits: BundleLimits
    ) -> tuple[list[ClosureEntry], list[ClosureLimitation]]: ...


@dataclass(frozen=True)
class ReadyToSealClosureSource:
    """Current default: enumerate the ready-to-seal artifacts by reference.

    When #444 lands, a ``SealedClosureSource`` enumerates from the verified seal
    manifest instead, without changing the bundle builder or archive rules.
    """

    @staticmethod
    def collect(
        run_dir: Path, run_id: str, *, limits: BundleLimits
    ) -> tuple[list[ClosureEntry], list[ClosureLimitation]]:
        entries: list[ClosureEntry] = []
        limitations: list[ClosureLimitation] = []
        collect_backend_evidence(run_dir, run_id, entries, limitations, limits)
        collect_evidence(run_dir, run_id, entries, limitations, limits)
        entries, conflicts = coalesce(entries)
        limitations.extend(conflicts)
        return entries, limitations


def _dedup(limitations: list[ClosureLimitation]) -> list[ClosureLimitation]:
    """Drop duplicate limitations and return them sorted by (code, subject, detail)."""
    seen: set[tuple[str, str, str | None]] = set()
    ordered: list[ClosureLimitation] = []
    for lim in limitations:
        key = (lim.code, lim.detail, lim.subject)
        if key not in seen:
            seen.add(key)
            ordered.append(lim)
    return sorted(ordered, key=lambda lim: (lim.code, lim.subject or "", lim.detail))


def build_closure(
    run_dir: Path,
    run_id: str,
    *,
    seal_verifier: SealVerifier | None = None,
    source: ClosureSource | None = None,
    limits: BundleLimits = DEFAULT_LIMITS,
) -> VerifiedClosure:
    """Assemble the verified closure for ``run_id`` under ``run_dir``.

    Reference-driven, no-follow, and honest about the seal: never scans the run
    tree, never fabricates a missing source, never treats a readiness state as a
    verified seal.
    """
    verifier = seal_verifier if seal_verifier is not None else UnsealedClosureVerifier()
    collector = source if source is not None else ReadyToSealClosureSource()
    seal = verifier.verify(run_id)
    entries, limitations = collector.collect(run_dir, run_id, limits=limits)
    all_limitations = list(seal.limitations) + limitations
    return VerifiedClosure(
        run_id=run_id,
        seal=seal,
        entries=tuple(entries),
        limitations=tuple(_dedup(all_limitations)),
    )


__all__ = [
    "SealScope",
    "ClosureLimitation",
    "Disclosures",
    "ClosureEntry",
    "SealBinding",
    "VerifiedClosure",
    "SealVerifier",
    "UnsealedClosureVerifier",
    "ClosureSource",
    "ReadyToSealClosureSource",
    "build_closure",
]
