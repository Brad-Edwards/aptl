"""Configuration API endpoints."""

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends

from aptl.api.deps import get_config, get_project_dir
from aptl.api.schemas import ConfigResponse
from aptl.core.config import ContainerSettings
from aptl.utils.logging import get_logger

log = get_logger("api.config")

router = APIRouter(tags=["config"])


def _load_config_response(project_dir: Path) -> ConfigResponse:
    """Build a ConfigResponse from the current configuration."""
    config = get_config(project_dir)
    return ConfigResponse(
        lab_name=config.lab.name,
        network_subnet=config.lab.network_subnet,
        containers={
            name: getattr(config.containers, name)
            for name in ContainerSettings.model_fields
        },
        run_storage_backend=config.run_storage.backend,
    )


@router.get("/config")
async def get_config_endpoint(
    project_dir: Path = Depends(get_project_dir),
) -> ConfigResponse:
    """Get the current APTL configuration."""
    log.info("GET /config")
    return await asyncio.to_thread(_load_config_response, project_dir)
