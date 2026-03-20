"""Configuration API endpoints."""

import asyncio

from fastapi import APIRouter

from aptl.api.deps import get_config, get_project_dir
from aptl.api.schemas import ConfigResponse

router = APIRouter(tags=["config"])


def _load_config_response() -> ConfigResponse:
    """Build a ConfigResponse from the current configuration."""
    project_dir = get_project_dir()
    config = get_config(project_dir)
    return ConfigResponse(
        lab_name=config.lab.name,
        network_subnet=config.lab.network_subnet,
        containers={
            name: getattr(config.containers, name)
            for name in [
                "wazuh", "victim", "kali", "reverse",
                "enterprise", "soc", "mail", "fileshare", "dns",
            ]
        },
        run_storage_backend=config.run_storage.backend,
    )


@router.get("/config")
async def get_config_endpoint() -> ConfigResponse:
    """Get the current APTL configuration."""
    return await asyncio.to_thread(_load_config_response)
