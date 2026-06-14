"""HTTP surface for the interactive console.

Sessions, scratchpads, and the MCP registry are served as JSON; a single
agent turn is streamed back over SSE. A per-project :class:`ConsoleStore` is
cached so its in-memory state and write lock stay consistent across requests,
while the registry and provider are rebuilt per request (both cheap) so newly
built MCP servers or a freshly exported API key are picked up without a
restart.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException
from sse_starlette.sse import EventSourceResponse

from aptl.api.deps import get_project_dir
from aptl.console.models import (
    ConsoleState,
    MessageCreate,
    Scratchpad,
    ScratchpadCreate,
    ScratchpadUpdate,
    Session,
    SessionCreate,
    SessionUpdate,
)
from aptl.console.runtime import ConsoleRuntime
from aptl.console.store import ConsoleStore, NotFoundError
from aptl.utils.logging import get_logger

log = get_logger("api.console")

router = APIRouter(tags=["console"], prefix="/console")

# One store per project dir, keyed by resolved path. The store owns the lock
# guarding the on-disk state, so it must be a singleton per project.
_STORES: dict[str, ConsoleStore] = {}


def _store_for(project_dir: Path) -> ConsoleStore:
    key = str(project_dir.resolve())
    store = _STORES.get(key)
    if store is None:
        store = ConsoleStore.for_project(project_dir)
        _STORES[key] = store
    return store


def get_runtime(
    project_dir: Annotated[Path, Depends(get_project_dir)],
) -> ConsoleRuntime:
    return ConsoleRuntime(project_dir, store=_store_for(project_dir))


RuntimeDep = Annotated[ConsoleRuntime, Depends(get_runtime)]


def _not_found(exc: NotFoundError) -> HTTPException:
    return HTTPException(status_code=404, detail=str(exc))


@router.get("/state", response_model=ConsoleState)
async def get_state(runtime: RuntimeDep) -> ConsoleState:
    return runtime.state()


# ---- sessions -----------------------------------------------------------


@router.post("/sessions", response_model=Session)
async def create_session(body: SessionCreate, runtime: RuntimeDep) -> Session:
    servers = body.mcp_servers
    if servers is None:
        servers = runtime.default_servers_for(body.role)
    title = body.title or f"{body.role.value.capitalize()} session"
    session = Session(
        title=title,
        role=body.role,
        mcp_servers=servers,
        scratchpads=body.scratchpads or [],
    )
    return runtime.store.add_session(session)


@router.get("/sessions/{session_id}", response_model=Session)
async def get_session(session_id: str, runtime: RuntimeDep) -> Session:
    try:
        return runtime.store.get_session(session_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc


@router.patch("/sessions/{session_id}", response_model=Session)
async def update_session(
    session_id: str, body: SessionUpdate, runtime: RuntimeDep
) -> Session:
    try:
        session = runtime.store.get_session(session_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    if body.title is not None:
        session.title = body.title
    if body.role is not None:
        session.role = body.role
    if body.mcp_servers is not None:
        session.mcp_servers = body.mcp_servers
    if body.scratchpads is not None:
        session.scratchpads = body.scratchpads
    return runtime.store.update_session(session)


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str, runtime: RuntimeDep) -> dict:
    try:
        runtime.store.delete_session(session_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    return {"deleted": session_id}


@router.post("/sessions/{session_id}/messages")
async def post_message(
    session_id: str, body: MessageCreate, runtime: RuntimeDep
) -> EventSourceResponse:
    if not body.content.strip():
        raise HTTPException(status_code=422, detail="Message content is empty")
    try:
        runtime.store.get_session(session_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc

    async def _generator() -> AsyncGenerator[dict, None]:
        try:
            async for event in runtime.run_turn(session_id, body.content):
                yield {"event": event.get("type", "message"), "data": json.dumps(event)}
        except Exception as exc:  # noqa: BLE001 — last-ditch stream guard
            log.exception("Console stream failed: %s", exc)
            yield {"event": "error", "data": json.dumps({"type": "error", "message": str(exc)})}

    return EventSourceResponse(_generator())


# ---- scratchpads --------------------------------------------------------


@router.post("/scratchpads", response_model=Scratchpad)
async def create_scratchpad(body: ScratchpadCreate, runtime: RuntimeDep) -> Scratchpad:
    if not body.name.strip():
        raise HTTPException(status_code=422, detail="Scratchpad name is empty")
    if runtime.store.find_scratchpad_by_name(body.name) is not None:
        raise HTTPException(status_code=409, detail=f"Scratchpad {body.name!r} already exists")
    return runtime.store.add_scratchpad(Scratchpad(name=body.name, content=body.content))


@router.patch("/scratchpads/{pad_id}", response_model=Scratchpad)
async def update_scratchpad(
    pad_id: str, body: ScratchpadUpdate, runtime: RuntimeDep
) -> Scratchpad:
    try:
        pad = runtime.store.get_scratchpad(pad_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    if body.name is not None:
        pad.name = body.name
    if body.content is not None:
        pad.content = body.content
    return runtime.store.update_scratchpad(pad)


@router.delete("/scratchpads/{pad_id}")
async def delete_scratchpad(pad_id: str, runtime: RuntimeDep) -> dict:
    try:
        runtime.store.delete_scratchpad(pad_id)
    except NotFoundError as exc:
        raise _not_found(exc) from exc
    return {"deleted": pad_id}
