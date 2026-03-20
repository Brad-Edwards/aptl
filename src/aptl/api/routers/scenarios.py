"""Scenario API endpoints."""

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from aptl.api.deps import get_project_dir
from aptl.api.schemas import ScenarioSummary
from aptl.core.scenarios import (
    ScenarioDefinition,
    ScenarioNotFoundError,
    ScenarioValidationError,
    find_scenarios,
    load_scenario,
)
from aptl.utils.logging import get_logger

log = get_logger("api.scenarios")

router = APIRouter(tags=["scenarios"])


def _scenarios_dir(project_dir: Path) -> Path:
    """Return the scenarios directory."""
    return project_dir / "scenarios"


def _load_all_scenarios(project_dir: Path) -> list[ScenarioSummary]:
    """Load all valid scenarios from the scenarios directory."""
    paths = find_scenarios(_scenarios_dir(project_dir))
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


def _load_single_scenario(
    scenario_id: str, project_dir: Path
) -> ScenarioDefinition:
    """Find and load a scenario by ID."""
    paths = find_scenarios(_scenarios_dir(project_dir))
    for path in paths:
        try:
            scenario = load_scenario(path)
            if scenario.metadata.id == scenario_id:
                return scenario
        except (ScenarioValidationError, FileNotFoundError):
            continue
    raise ScenarioNotFoundError(scenario_id)


@router.get("/scenarios")
async def list_scenarios(
    project_dir: Path = Depends(get_project_dir),
) -> list[ScenarioSummary]:
    """List all available scenarios."""
    log.info("GET /scenarios")
    result = await asyncio.to_thread(_load_all_scenarios, project_dir)
    log.info("GET /scenarios -> %d scenarios", len(result))
    return result


@router.get("/scenarios/{scenario_id}")
async def get_scenario(
    scenario_id: str,
    project_dir: Path = Depends(get_project_dir),
) -> dict:
    """Get full scenario definition by ID."""
    log.info("GET /scenarios/%s", scenario_id)
    try:
        scenario = await asyncio.to_thread(
            _load_single_scenario, scenario_id, project_dir
        )
    except ScenarioNotFoundError:
        log.warning("Scenario not found: %s", scenario_id)
        raise HTTPException(status_code=404, detail=f"Scenario not found: {scenario_id}")
    return scenario.model_dump()
