"""Lab lifecycle API endpoints."""

import asyncio
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Depends
from sse_starlette.sse import EventSourceResponse

from aptl.api.deps import get_project_dir
from aptl.api.schemas import (
    ContainerInfo,
    LabActionResponse,
    LabStatusResponse,
)
from aptl.core.lab import (
    LabResult,
    lab_status as core_lab_status,
    orchestrate_lab_start,
    stop_lab as core_stop_lab,
)
from aptl.utils.logging import get_logger

log = get_logger("api.lab")

router = APIRouter(tags=["lab"])

# SSE circuit breaker settings
MAX_CONSECUTIVE_ERRORS = 10


def _build_status_response(project_dir: Path) -> LabStatusResponse:
    """Build a LabStatusResponse from the core lab_status function."""
    status = core_lab_status(project_dir=project_dir)
    containers = [ContainerInfo.from_compose_dict(c) for c in status.containers]
    return LabStatusResponse(
        running=status.running,
        containers=containers,
        error=status.error or None,
    )


@router.get("/lab/status")
async def lab_status(
    project_dir: Path = Depends(get_project_dir),
) -> LabStatusResponse:
    """Get current lab status including container information."""
    log.info("GET /lab/status")
    response = await asyncio.to_thread(_build_status_response, project_dir)
    log.info("GET /lab/status -> running=%s containers=%d", response.running, len(response.containers))
    return response


@router.post("/lab/start")
async def lab_start(
    project_dir: Path = Depends(get_project_dir),
) -> LabActionResponse:
    """Start the lab environment.

    Blocks until orchestration completes or times out (30 min).
    """
    log.info("POST /lab/start")
    try:
        result: LabResult = await asyncio.wait_for(
            asyncio.to_thread(orchestrate_lab_start, project_dir),
            timeout=1800,
        )
    except asyncio.TimeoutError:
        log.exception("Lab start timed out after 1800s")
        return LabActionResponse(
            success=False,
            error="Lab start timed out after 1800s",
        )
    log.info("POST /lab/start -> success=%s", result.success)
    return LabActionResponse(
        success=result.success,
        message=result.message,
        error=result.error or None,
    )


@router.post("/lab/stop")
async def lab_stop(
    project_dir: Path = Depends(get_project_dir),
) -> LabActionResponse:
    """Stop the lab environment."""
    log.info("POST /lab/stop")
    result: LabResult = await asyncio.to_thread(
        core_stop_lab, project_dir=project_dir
    )
    log.info("POST /lab/stop -> success=%s", result.success)
    return LabActionResponse(
        success=result.success,
        message=result.message,
        error=result.error or None,
    )


async def _lab_event_generator(
    project_dir: Path,
) -> AsyncGenerator[dict, None]:
    """Poll lab status and yield SSE events on state changes.

    Implements exponential backoff on errors and terminates after
    MAX_CONSECUTIVE_ERRORS consecutive failures (circuit breaker).
    """
    log.info("SSE connection opened")
    previous_running: bool | None = None
    previous_containers: list[str] = []
    consecutive_errors = 0

    while True:
        try:
            response = await asyncio.to_thread(
                _build_status_response, project_dir
            )
            consecutive_errors = 0
            current_containers = [c.name for c in response.containers]

            # Emit event if state changed or on first poll
            if (
                previous_running is None
                or response.running != previous_running
                or current_containers != previous_containers
            ):
                yield {
                    "event": "lab_status",
                    "data": response.model_dump_json(),
                }
                previous_running = response.running
                previous_containers = current_containers

        except Exception as exc:
            consecutive_errors += 1
            log.warning(
                "SSE poll error (%d/%d): %s",
                consecutive_errors,
                MAX_CONSECUTIVE_ERRORS,
                exc,
            )
            yield {
                "event": "error",
                "data": "Internal error while polling lab status",
            }
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                log.error(
                    "SSE circuit breaker tripped after %d consecutive errors, closing stream",
                    MAX_CONSECUTIVE_ERRORS,
                )
                return
            # Exponential backoff: 5, 10, 20, 40, 60, 60, ...
            backoff = min(5 * (2 ** (consecutive_errors - 1)), 60)
            await asyncio.sleep(backoff)
            continue

        await asyncio.sleep(5)

    log.info("SSE connection closed")


@router.get("/lab/events")
async def lab_events(
    project_dir: Path = Depends(get_project_dir),
) -> EventSourceResponse:
    """SSE stream of lab status changes.

    Polls lab status every 5 seconds and emits events when the
    running state or container list changes.
    """
    log.info("GET /lab/events — starting SSE stream")
    return EventSourceResponse(_lab_event_generator(project_dir))
