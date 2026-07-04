"""Scenario catalog API endpoints (UI-008c list + UI-008d detail).

Exposes the curated ACES scenario catalog as narrow card summaries for the Lab
Home entry points, and a backend-owned workbench *detail* projection for the
``/scenarios/[id]`` route. Both project from the curated catalog
(``scenarios/catalog.json``) and the ACES SDL parser authority; neither exposes
the internal catalog ``path`` locator or raw parser output.
"""

import asyncio
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from aptl.api.deps import get_project_dir
from aptl.api.scenario_projection import (
    build_scenario_detail,
    build_scenario_summary,
    invalid_scenario_summary,
)
from aptl.api.schemas import ScenarioDetailResponse, ScenarioSummaryResponse
from aptl.core.scenario_catalog import (
    CATALOG_RELATIVE_PATH,
    load_scenario_catalog,
    resolve_and_parse_scenario,
)
from aptl.core.scenarios import ScenarioNotFoundError, ScenarioValidationError
from aptl.utils.logging import get_logger

log = get_logger("api.scenarios")

router = APIRouter(tags=["scenarios"])


def _load_scenario_summaries(project_dir: Path) -> list[ScenarioSummaryResponse]:
    """Project the curated scenario catalog into enriched card-summary DTOs.

    Returns an empty list when no catalog file is present (a lab need not ship
    a curated catalog). A malformed or schema-invalid catalog is logged and
    degrades to an empty list. An individual entry whose ACES SDL cannot be
    resolved/parsed still lists — with an invalid validation state and no
    required containers — so one broken scenario never fails the whole page.
    """
    if not (project_dir / CATALOG_RELATIVE_PATH).is_file():
        return []
    try:
        catalog = load_scenario_catalog(project_dir)
    except ValueError as exc:
        log.warning("Scenario catalog unreadable; returning empty list: %s", exc)
        return []
    summaries: list[ScenarioSummaryResponse] = []
    for entry in catalog.scenarios:
        try:
            _, scenario = resolve_and_parse_scenario(project_dir, entry.id)
        except (ScenarioNotFoundError, ScenarioValidationError) as exc:
            log.warning(
                "Scenario '%s' failed to project for summary: %s", entry.id, exc
            )
            summaries.append(invalid_scenario_summary(entry))
            continue
        summaries.append(build_scenario_summary(entry, scenario))
    return summaries


def _load_scenario_detail(
    project_dir: Path, scenario_id: str
) -> ScenarioDetailResponse:
    """Resolve + project one scenario, mapping failures to redacted HTTP errors."""
    try:
        entry, scenario = resolve_and_parse_scenario(project_dir, scenario_id)
    except ScenarioNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Unknown scenario") from exc
    except ScenarioValidationError as exc:
        # The exception message is already redacted; the response detail stays
        # generic so neither the catalog path nor parser output can surface.
        raise HTTPException(
            status_code=502, detail="Scenario projection is currently unavailable."
        ) from exc
    return build_scenario_detail(entry, scenario)


@router.get("/scenarios")
async def list_scenarios(
    project_dir: Annotated[Path, Depends(get_project_dir)],
) -> list[ScenarioSummaryResponse]:
    """List the curated ACES scenario catalog as enriched card summaries."""
    log.info("GET /scenarios")
    return await asyncio.to_thread(_load_scenario_summaries, project_dir)


@router.get("/scenarios/{scenario_id}")
async def get_scenario_detail(
    scenario_id: str,
    project_dir: Annotated[Path, Depends(get_project_dir)],
) -> ScenarioDetailResponse:
    """Project one curated scenario into a backend-owned workbench detail."""
    log.info("GET /scenarios/%s", scenario_id)
    return await asyncio.to_thread(_load_scenario_detail, project_dir, scenario_id)
