"""Live experiment execution (#437/#459): drive admitted trials to sealed records.

This package is the production terminal-attempt authority ADR-050 reserves for
the execution lifecycle. :class:`ExperimentExecutor` consumes an
:class:`AdmittedExperiment` (the admitted plan plus its owner-native task,
scenario, apparatus, and participant identities) and, for each planned trial,
runs the injected workload under the evidence coordinator, normalizes the
terminal cause, and calls :func:`~aptl.core.archival.finalize_terminal_attempt`
exactly once — producing the sealed conformant ACES ``experiment-run/v1`` record
EXP-009 requires for every terminal execution attempt.
"""

from __future__ import annotations

from aptl.core.execution.executor import (
    AdmittedExperiment,
    ExperimentExecutor,
    TrialExecutionContext,
    TrialOutcome,
    TrialTerminalSignal,
    normalize_terminal_cause,
)

__all__ = [
    "AdmittedExperiment",
    "ExperimentExecutor",
    "TrialExecutionContext",
    "TrialOutcome",
    "TrialTerminalSignal",
    "normalize_terminal_cause",
]
