"""Configuration API endpoints."""

import asyncio
import os
from pathlib import Path

from fastapi import APIRouter, Depends

from aptl import __version__
from aptl.api.deps import get_config, get_project_dir
from aptl.api.middleware.bff import effective_allowed_hosts
from aptl.api.schemas import ConfigResponse, WebServeInfo
from aptl.core.config import ContainerSettings
from aptl.utils.logging import get_logger

log = get_logger("api.config")

router = APIRouter(tags=["config"])


def _web_serve_info(deployment_provider: str) -> WebServeInfo:
    """Project non-secret web-serve facts (UI-008f).

    Sources only non-secret values: the package build version, the effective
    Host allow-list (loopback plus ``APTL_ALLOWED_HOSTS``), the browser-facing
    public origin (``APTL_WEB_PUBLIC_ORIGIN``, trailing slash trimmed to match
    the launch-URL normalisation in ``aptl.cli.web``), and the deployment
    provider. Never reads the API token, session factors, cookies, private keys,
    or raw ``.env`` content.
    """
    public_origin = os.environ.get("APTL_WEB_PUBLIC_ORIGIN")
    return WebServeInfo(
        build_version=__version__,
        allowed_hosts=effective_allowed_hosts(),
        public_origin=public_origin.rstrip("/") if public_origin else None,
        deployment_provider=deployment_provider,
    )


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
        web=_web_serve_info(config.deployment.provider),
    )


@router.get("/config")
async def get_config_endpoint(
    project_dir: Path = Depends(get_project_dir),
) -> ConfigResponse:
    """Get the current APTL configuration."""
    log.info("GET /config")
    return await asyncio.to_thread(_load_config_response, project_dir)
