"""Shared corpus-backed fixtures for the EXP-009 archival tests.

The installed RAES corpus ships a valid ``experiment-run-v1`` reference and its
paired ``experiment-task-v1`` reference that already cross-validate. These
helpers decompose the reference run into a :class:`TerminalAttemptContext` so
tests exercise the real composer + real RAES cross-artifact validators against
ground-truth sub-models rather than hand-rolled approximations.
"""

from __future__ import annotations

import json
from pathlib import Path

import raes_contracts
from raes_contracts.contracts import ExperimentRunModel, ExperimentTaskModel

from aptl.core.archival.context import TerminalAttemptContext
from aptl.core.archival.status import TerminalCause

_CORPUS = (
    Path(raes_contracts.__file__).parent
    / "_corpus"
    / "fixtures"
    / "experiment-core"
)


def reference_task() -> ExperimentTaskModel:
    payload = json.loads(
        (_CORPUS / "experiment-task-v1" / "valid" / "reference.json").read_text()
    )
    return ExperimentTaskModel.model_validate(payload)


def reference_run() -> ExperimentRunModel:
    payload = json.loads(
        (_CORPUS / "experiment-run-v1" / "valid" / "reference.json").read_text()
    )
    return ExperimentRunModel.model_validate(payload)


def completed_context(**overrides: object) -> TerminalAttemptContext:
    """A COMPLETED/succeeded terminal context reconstructed from the corpus run."""
    run = reference_run()
    task = reference_task()
    base = {
        "attempt_id": run.run_id,
        "run_version": run.run_version,
        "terminal_cause": TerminalCause.COMPLETED,
        "evaluator_outcome": run.outcome_status,
        "task": task,
        "scenario_snapshot_ref": run.scenario_snapshot_ref,
        "apparatus_context": run.apparatus_context,
        "parameter_set": tuple(run.parameter_set),
        "stochastic_controls": tuple(run.stochastic_controls),
        "clock_context": run.clock_context,
        "traceability": run.traceability,
        "evidence_artifacts": tuple(run.evidence_artifacts),
        "result_summaries": dict(run.result_summaries),
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "participant_implementation_provenance": run.participant_implementation_provenance,
        "realized_bindings": tuple(run.realized_bindings),
        "stochastic_draws": tuple(run.stochastic_draws),
        "realized_form_disclosures": tuple(run.realized_form_disclosures),
        "augmentation_disclosures": tuple(run.augmentation_disclosures),
        "used_refs": tuple(run.used_refs),
        "generated_refs": tuple(run.generated_refs),
    }
    base.update(overrides)
    return TerminalAttemptContext(**base)  # type: ignore[arg-type]
