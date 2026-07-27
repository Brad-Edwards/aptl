"""Immutable trial-plan value objects and canonical JSON projection."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

import rfc8785
from raes_contracts.contracts import (
    ParticipantConfigurationResultModel,
    RealizedBindingProvenanceModel,
)

from aptl.core.experiment.policy import OrderingKind

if TYPE_CHECKING:
    from aptl.core.experiment.capture_registry import CaptureBinding

_PLAN_ID_PREFIX = "plan-"
_PLAN_PROJECTION_SCHEMA = "aptl-experiment-trial-plan/v3"


@dataclass(frozen=True)
class PlannedTrial:
    """One immutable planned trial coordinate within a :class:`TrialPlan`."""

    planned_trial_id: str
    condition_id: str | None
    replication_ordinal: int
    ordering_index: int
    factor_levels: tuple[tuple[str, str], ...]
    parameter_bindings: tuple[tuple[str, object], ...]
    stochastic_seeds: tuple[tuple[str, str], ...]
    scenario_snapshot_digest: str | None
    capture_spec_refs: tuple[str, ...]
    realized_bindings: tuple[RealizedBindingProvenanceModel, ...] = ()
    participant_configurations: tuple[ParticipantConfigurationResultModel, ...] = ()
    apparatus_configuration: tuple[tuple[str, object], ...] = ()


@dataclass(frozen=True)
class TrialPlan:
    """An immutable, deterministically-derived plan for one admitted spec."""

    plan_id: str
    policy_version: str
    source_set_digest: str
    ordering_kind: OrderingKind
    trials: tuple[PlannedTrial, ...]
    capture_bindings: tuple[CaptureBinding, ...]
    canonical_bytes: bytes
    plan_digest: str


def _trial_projection(trial: PlannedTrial) -> dict[str, object]:
    """Project one planned trial into its canonical-JSON-ready shape."""

    return {
        "planned_trial_id": trial.planned_trial_id,
        "condition_id": trial.condition_id,
        "replication_ordinal": trial.replication_ordinal,
        "ordering_index": trial.ordering_index,
        "factor_levels": dict(trial.factor_levels),
        "parameter_bindings": dict(trial.parameter_bindings),
        "stochastic_seeds": dict(trial.stochastic_seeds),
        "scenario_snapshot_digest": trial.scenario_snapshot_digest,
        "capture_spec_refs": list(trial.capture_spec_refs),
        "realized_bindings": [
            binding.model_dump(mode="json", exclude_none=True)
            for binding in trial.realized_bindings
        ],
        "participant_configurations": [
            configuration.model_dump(mode="json", exclude_none=True)
            for configuration in trial.participant_configurations
        ],
        "apparatus_configuration": dict(trial.apparatus_configuration),
    }


def canonicalize_trial_plan(
    *,
    policy_version: str,
    source_set_digest: str,
    ordering_kind: OrderingKind,
    trials: tuple[PlannedTrial, ...],
    capture_bindings: Sequence[CaptureBinding],
) -> tuple[bytes, str, str]:
    """Return canonical bytes, digest, and ID for one complete trial plan."""

    projection = {
        "plan_schema": _PLAN_PROJECTION_SCHEMA,
        "policy_version": policy_version,
        "source_set_digest": source_set_digest,
        "ordering_kind": ordering_kind.value,
        "trials": [_trial_projection(trial) for trial in trials],
        "capture_bindings": [
            binding.binding_projection() for binding in capture_bindings
        ],
    }
    canonical_bytes = rfc8785.dumps(projection)
    digest_hex = hashlib.sha256(canonical_bytes).hexdigest()
    return (
        canonical_bytes,
        f"sha256:{digest_hex}",
        _PLAN_ID_PREFIX + digest_hex,
    )


__all__ = ["PlannedTrial", "TrialPlan", "canonicalize_trial_plan"]
