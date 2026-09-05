"""Scenario API projected from the configured validated environment pack."""

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
from aptl.api.schemas import (
    ScenarioDetailResponse,
    ScenarioPackIdentityResponse,
    ScenarioSummaryResponse,
)
from aptl.core.scenario_catalog import (
    ScenarioCatalog,
    load_scenario_catalog,
    resolve_acquired_scenario,
)
from aptl.core.scenarios import ScenarioNotFoundError, ScenarioValidationError
from aptl.utils.logging import get_logger

log = get_logger("api.scenarios")
router = APIRouter(tags=["scenarios"])


def _pack_response(catalog: ScenarioCatalog) -> ScenarioPackIdentityResponse:
    identity = catalog.pack_identity
    return ScenarioPackIdentityResponse(
        id=identity.pack_id,
        version=identity.pack_version,
        set_digest=identity.set_digest,
        maturity=catalog.maturity,
    )


def _load_scenario_summaries(project_dir: Path) -> list[ScenarioSummaryResponse]:
    """Resolve one pack once and project its operator-facing catalog entries."""
    try:
        catalog = load_scenario_catalog(project_dir)
    except ValueError as exc:
        log.warning("Acquired scenario catalog unavailable; returning empty list: %s", exc)
        return []
    pack = _pack_response(catalog)
    summaries: list[ScenarioSummaryResponse] = []
    for entry in catalog.scenarios:
        try:
            resolved = resolve_acquired_scenario(
                project_dir, entry.id, catalog=catalog
            )
        except (ScenarioNotFoundError, ScenarioValidationError) as exc:
            log.warning("Scenario '%s' failed to project for summary: %s", entry.id, exc)
            summaries.append(invalid_scenario_summary(entry, pack))
            continue
        summaries.append(build_scenario_summary(entry, resolved.scenario, pack))
    return summaries


def _load_scenario_detail(project_dir: Path, scenario_id: str) -> ScenarioDetailResponse:
    """Resolve one acquired scenario and project its bounded detail response."""
    try:
        catalog = load_scenario_catalog(project_dir)
        resolved = resolve_acquired_scenario(
            project_dir, scenario_id, catalog=catalog
        )
    except ScenarioNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Unknown scenario") from exc
    except (ScenarioValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=502, detail="Scenario projection is currently unavailable."
        ) from exc
    return build_scenario_detail(
        resolved.entry, resolved.scenario, _pack_response(catalog)
    )


@router.get("/scenarios")
async def list_scenarios(
    project_dir: Annotated[Path, Depends(get_project_dir)],
) -> list[ScenarioSummaryResponse]:
    log.info("GET /scenarios")
    return await asyncio.to_thread(_load_scenario_summaries, project_dir)


@router.get("/scenarios/{scenario_id}")
async def get_scenario_detail(
    scenario_id: str,
    project_dir: Annotated[Path, Depends(get_project_dir)],
) -> ScenarioDetailResponse:
    log.info("GET /scenarios/{scenario_id}")
    return await asyncio.to_thread(_load_scenario_detail, project_dir, scenario_id)
