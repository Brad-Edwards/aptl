"""Emergency kill switch API endpoint."""

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, Query

from aptl.api.deps import get_project_dir
from aptl.api.schemas import KillActionResponse
from aptl.core.kill import execute_kill
from aptl.utils.logging import get_logger

log = get_logger("api.kill")

router = APIRouter(tags=["kill"])


@router.post("/lab/kill")
async def lab_kill(
    containers: bool = Query(False, description="Also force-stop all lab containers"),
    project_dir: Path = Depends(get_project_dir),
) -> KillActionResponse:
    """Emergency kill switch: terminate all MCP processes and agent activity.

    Immediately sends SIGTERM (then SIGKILL) to all running MCP server
    processes. Optionally force-stops all lab Docker containers.
    Clears scenario session state and trace context files.
    """
    log.info("POST /lab/kill (containers=%s)", containers)

    result = await asyncio.to_thread(
        execute_kill,
        containers=containers,
        project_dir=project_dir,
    )

    log.info(
        "POST /lab/kill -> success=%s mcp=%d containers=%s",
        result.success,
        result.mcp_processes_killed,
        result.containers_stopped,
    )

    return KillActionResponse(
        success=result.success,
        mcp_processes_killed=result.mcp_processes_killed,
        containers_stopped=result.containers_stopped,
        session_cleared=result.session_cleared,
        errors=result.errors,
    )
