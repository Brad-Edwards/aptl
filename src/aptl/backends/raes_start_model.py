"""Shared DTOs for RAES scenario start outcomes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from raes_contracts.runtime_state import RuntimeSnapshot

from aptl.core.lab_types import LabResult

if TYPE_CHECKING:
    from raes_processor.models import ExecutionPlan
    from raes_runtime.registry import RuntimeTarget

    from aptl.backends.raes_realization_model import AptlRealization
    from aptl.core.runstore import RunStorageBackend
    from aptl.core.scenario_bundle import ScenarioBundle

DEFAULT_RAES_SCENARIO = Path("scenarios") / "techvault-operational.sdl.yaml"


@dataclass(frozen=True)
class AdmittedScenarioStart:
    """One admitted scenario execution, shared by pre-mutation steps and apply.

    Resolving the bundle, parsing it, building the runtime target, planning, and
    interpreting the provisioning plan are one admission. Lab start caches this
    before it mutates anything and hands the *same* object back to apply, so a
    pre-start decision and the deployment it precedes cannot disagree — and a
    staged env-pack is acquired and validated once per run rather than once per
    question asked about it (issue #951).
    """

    bundle: ScenarioBundle
    target: RuntimeTarget
    execution_plan: ExecutionPlan
    realization: AptlRealization | None


@dataclass(frozen=True)
class AcesRunTarget:
    """Resolved archive destination shared by orchestration and run records."""

    run_store: RunStorageBackend
    run_id: str


@dataclass
class AcesStartOutcome:
    """Reference-holder for start_raes_scenario outputs (REP-001 / ADR-044)."""

    lab_result: LabResult
    final_snapshot: RuntimeSnapshot
    realization_details: dict[str, Any]
    selected_profiles: list[str]
    scenario_path: Path | None
    manifest_payload: dict[str, Any] = field(default_factory=dict)
    pack_interaction_evidence: dict[str, Any] = field(default_factory=dict)
    retryable: bool = False
