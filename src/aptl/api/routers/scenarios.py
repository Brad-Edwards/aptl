"""Scenario API endpoints."""

import asyncio
from pathlib import Path

from fastapi import APIRouter, HTTPException

from aptl.api.deps import get_project_dir
from aptl.api.schemas import ScenarioSummary
from aptl.core.scenarios import (
    ScenarioDefinition,
    ScenarioNotFoundError,
    ScenarioValidationError,
    find_scenarios,
    load_scenario,
)

router = APIRouter(tags=["scenarios"])


def _scenarios_dir() -> Path:
    """Return the scenarios directory."""
    return get_project_dir() / "scenarios"


def _load_all_scenarios() -> list[ScenarioSummary]:
    """Load all valid scenarios from the scenarios directory."""
    paths = find_scenarios(_scenarios_dir())
    summaries: list[ScenarioSummary] = []
    for path in paths:
        try:
            scenario = load_scenario(path)
            summaries.append(
                ScenarioSummary(
                    id=scenario.metadata.id,
                    name=scenario.metadata.name,
                    description=scenario.metadata.description,
                    difficulty=scenario.metadata.difficulty.value,
                    mode=scenario.mode.value,
                    estimated_minutes=scenario.metadata.estimated_minutes,
                    tags=scenario.metadata.tags,
                    containers_required=scenario.containers.required,
                )
            )
        except (ScenarioValidationError, FileNotFoundError):
            # Skip invalid scenarios — they'll surface in CLI validation
            continue
    return summaries


def _load_single_scenario(scenario_id: str) -> ScenarioDefinition:
    """Find and load a scenario by ID."""
    paths = find_scenarios(_scenarios_dir())
    for path in paths:
        try:
            scenario = load_scenario(path)
            if scenario.metadata.id == scenario_id:
                return scenario
        except (ScenarioValidationError, FileNotFoundError):
            continue
    raise ScenarioNotFoundError(scenario_id)


@router.get("/scenarios")
async def list_scenarios() -> list[ScenarioSummary]:
    """List all available scenarios."""
    return await asyncio.to_thread(_load_all_scenarios)


@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str) -> dict:
    """Get full scenario definition by ID."""
    try:
        scenario = await asyncio.to_thread(_load_single_scenario, scenario_id)
    except ScenarioNotFoundError:
        raise HTTPException(status_code=404, detail=f"Scenario not found: {scenario_id}")
    return scenario.model_dump()
