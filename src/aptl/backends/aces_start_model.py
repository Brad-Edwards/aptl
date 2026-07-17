"""Shared DTOs for ACES scenario start outcomes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aces_contracts.runtime_state import RuntimeSnapshot

from aptl.core.lab_types import LabResult

DEFAULT_ACES_SCENARIO = Path("scenarios") / "techvault-operational.sdl.yaml"


@dataclass
class AcesStartOutcome:
    """Reference-holder for start_aces_scenario outputs (REP-001 / ADR-044)."""

    lab_result: LabResult
    final_snapshot: RuntimeSnapshot
    realization_details: dict[str, Any]
    selected_profiles: list[str]
    scenario_path: Path | None
    manifest_payload: dict[str, Any] = field(default_factory=dict)
    retryable: bool = False
