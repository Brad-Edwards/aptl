"""Dependency injection and shared constants for the APTL API."""

from pathlib import Path
from typing import Optional

from fastapi import HTTPException

from aptl.core.config import AptlConfig, find_config, load_config
from aptl.utils.logging import get_logger

log = get_logger("api.deps")

# Trusted origins for CORS and WebSocket origin validation.
# CORS middleware does not protect WebSocket upgrade requests, so
# the terminal endpoint checks this set independently.
ALLOWED_ORIGINS: set[str] = {
    "http://localhost:3000",
    "http://localhost:5173",
}


def get_project_dir() -> Path:
    """Return the project root directory.

    Checks APTL_PROJECT_DIR env var first, then falls back to cwd.
    Raises HTTP 503 if the resolved directory does not exist.
    """
    import os

    env_dir = os.environ.get("APTL_PROJECT_DIR")
    if env_dir:
        p = Path(env_dir)
    else:
        p = Path.cwd()
    if not p.is_dir():
        log.error("Project directory does not exist: %s", p)
        raise HTTPException(
            status_code=503,
            detail="Project directory not found or not configured",
        )
    return p


def get_config(project_dir: Optional[Path] = None) -> AptlConfig:
    """Load the APTL configuration.

    Args:
        project_dir: Project directory to search for aptl.json.
            Defaults to get_project_dir().

    Returns:
        Validated AptlConfig, or a default config if no file is found.
    """
    search_dir = project_dir or get_project_dir()
    config_path = find_config(search_dir)
    if config_path is None:
        return AptlConfig()
    return load_config(config_path)
