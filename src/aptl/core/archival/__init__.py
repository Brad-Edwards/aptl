"""Terminal-attempt ACES archival run production and atomic sealing (EXP-009 /
issue #444).

This package composes the public RAES ``ExperimentRunModel``
(``schema_version="experiment-run/v1"``) for every terminal execution attempt
and seals the run archive atomically (ADR-050 "Terminal Attempt Archival and
Atomic Seal Boundary"). It adds **no** APTL mirror of any RAES contract: it
assembles owner-native RAES sub-models — apparatus context, participant
provenance, evidence records, evaluator result summaries — into the top-level
run record, maps the execution controller's terminal cause onto RAES run/outcome
status, and commits an atomic seal marker.

The live execution controller that produces terminal attempts (issues
#437/#459) owns *when* an attempt becomes terminal; this package is the archival
consumer it hands a :class:`~aptl.core.archival.context.TerminalAttemptContext`.
It never rediscovers a run from mutable configuration, active-session state,
timestamps, or arbitrary archive paths.
"""

from __future__ import annotations

from aptl.core.archival.context import TerminalAttemptContext
from aptl.core.archival.coordinator import SealResult, finalize_terminal_attempt
from aptl.core.archival.discovery_index import (
    DiscoveryIndex,
    IndexCorruptionError,
    IndexEntry,
)
from aptl.core.archival.run_record import build_experiment_run_model
from aptl.core.archival.seal import SealedArtifactSpec, SealLimitation
from aptl.core.archival.status import (
    TerminalCause,
    TerminalStatus,
    map_terminal_cause,
)
from aptl.core.archival.verify import (
    SealVerificationError,
    VerifiedArchive,
    verify_sealed_archive,
)

__all__ = [
    "DiscoveryIndex",
    "IndexCorruptionError",
    "IndexEntry",
    "SealLimitation",
    "SealResult",
    "SealVerificationError",
    "SealedArtifactSpec",
    "TerminalAttemptContext",
    "TerminalCause",
    "TerminalStatus",
    "VerifiedArchive",
    "build_experiment_run_model",
    "finalize_terminal_attempt",
    "map_terminal_cause",
    "verify_sealed_archive",
]
