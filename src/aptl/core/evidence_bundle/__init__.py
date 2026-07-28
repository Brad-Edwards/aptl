"""EXP-008 portable research evidence bundle export.

Packages a run's verified artifact closure into a portable, self-describing
bundle: canonical RAES evidence + backend evidence, a machine-readable
inventory/data-dictionary, optional loss-accounted projections (JSONL, Parquet,
OCSF-aligned), and a deterministic archive a third party can verify without
importing APTL internals.

Export is packaging/projection over a verified closure — never validation,
sanitation, statistical analysis, claim selection, or a publishability
certification (see ``docs/architecture/exp-008-portable-evidence-bundle-preflight.md``).
"""

from __future__ import annotations

from aptl.core.evidence_bundle.build import BundleBuildResult, build_evidence_bundle
from aptl.core.evidence_bundle.errors import BundleError
from aptl.core.evidence_bundle.verify import VerificationReport, verify_bundle

__all__ = [
    "BundleError",
    "BundleBuildResult",
    "build_evidence_bundle",
    "VerificationReport",
    "verify_bundle",
]
