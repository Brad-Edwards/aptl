"""Scenario catalog summary API endpoint (UI-008c).

Exposes the curated ACES scenario catalog as narrow card summaries for the Lab
Home scenario entry points. Scenario *detail* (workbench) projection is a
separate slice and stays absent here.
"""

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends

from aptl.api.deps import get_project_dir
from aptl.api.schemas import ScenarioSummaryResponse
from aptl.core.scenario_catalog import CATALOG_RELATIVE_PATH, load_scenario_catalog
from aptl.utils.logging import get_logger

log = get_logger("api.scenarios")

router = APIRouter(tags=["scenarios"])


def _load_scenario_summaries(project_dir: Path) -> list[ScenarioSummaryResponse]:
    """Project the curated scenario catalog into card-summary DTOs.

    Returns an empty list when no catalog file is present (a lab need not ship
    a curated catalog). A malformed or schema-invalid catalog is logged and also
    degrades to an empty list, so Lab Home shows "No scenarios found" rather than
    failing the whole page on a config error.
    """
    if not (project_dir / CATALOG_RELATIVE_PATH).is_file():
        return []
    try:
        catalog = load_scenario_catalog(project_dir)
    except ValueError as exc:
        log.warning("Scenario catalog unreadable; returning empty list: %s", exc)
        return []
    return [
        ScenarioSummaryResponse(
            id=entry.id, name=entry.name, description=entry.description
        )
        for entry in catalog.scenarios
    ]


@router.get("/scenarios")
async def list_scenarios(
    project_dir: Path = Depends(get_project_dir),
) -> list[ScenarioSummaryResponse]:
    """List the curated ACES scenario catalog as card summaries."""
    log.info("GET /scenarios")
    return await asyncio.to_thread(_load_scenario_summaries, project_dir)
