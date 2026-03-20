"""Lab lifecycle API endpoints."""

import asyncio
from typing import AsyncGenerator

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from aptl.api.deps import get_config, get_project_dir
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

router = APIRouter(tags=["lab"])


def _build_status_response() -> LabStatusResponse:
    """Build a LabStatusResponse from the core lab_status function."""
    project_dir = get_project_dir()
    status = core_lab_status(project_dir=project_dir)
    containers = [ContainerInfo.from_compose_dict(c) for c in status.containers]
    return LabStatusResponse(
        running=status.running,
        containers=containers,
        error=status.error,
    )


@router.get("/lab/status")
async def lab_status() -> LabStatusResponse:
    """Get current lab status including container information."""
    return await asyncio.to_thread(_build_status_response)


@router.post("/lab/start")
async def lab_start() -> LabActionResponse:
    """Start the lab environment.

    Runs the full orchestration in a background thread since it can
    take several minutes. Returns immediately with the result.
    """
    project_dir = get_project_dir()
    result: LabResult = await asyncio.to_thread(
        orchestrate_lab_start, project_dir
    )
    return LabActionResponse(
        success=result.success,
        message=result.message,
        error=result.error,
    )


@router.post("/lab/stop")
async def lab_stop() -> LabActionResponse:
    """Stop the lab environment."""
    project_dir = get_project_dir()
    result: LabResult = await asyncio.to_thread(
        core_stop_lab, project_dir=project_dir
    )
    return LabActionResponse(
        success=result.success,
        message=result.message,
        error=result.error,
    )


async def _lab_event_generator() -> AsyncGenerator[dict, None]:
    """Poll lab status and yield SSE events on state changes."""
    previous_running: bool | None = None
    previous_containers: list[str] = []

    while True:
        try:
            response = await asyncio.to_thread(_build_status_response)
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
            yield {
                "event": "error",
                "data": str(exc),
            }

        await asyncio.sleep(5)


@router.get("/lab/events")
async def lab_events() -> EventSourceResponse:
    """SSE stream of lab status changes.

    Polls lab status every 5 seconds and emits events when the
    running state or container list changes.
    """
    return EventSourceResponse(_lab_event_generator())
