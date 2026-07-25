"""Dedicated participant browser surface for the in-appliance workbench."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from aptl.workbench.profiles import profile_for
from aptl.workbench.runtime import WorkbenchRuntime, WorkbenchStateError

ParticipantAuthorizer = Callable[[Request], bool]


def create_participant_workbench_app(
    runtime: WorkbenchRuntime, authorizer: ParticipantAuthorizer
) -> FastAPI:
    """Create a participant-only app, deliberately separate from operator APIs."""
    app = FastAPI(title="APTL Participant Workbench", docs_url=None, redoc_url=None)

    def require_participant_session(request: Request) -> None:
        if not authorizer(request):
            raise HTTPException(status_code=401, detail="Participant session required")

    session = [Depends(require_participant_session)]

    @app.get("/", response_class=HTMLResponse, dependencies=session)
    async def workbench_page() -> str:
        """Serve a minimal browser entrypoint without an operator console."""
        return """<!doctype html><html><head><title>APTL Workbench</title></head>
<body><main><h1>APTL participant workbench</h1><p>Use the assigned profile.</p></main></body></html>"""

    @app.get("/workbench", dependencies=session)
    async def workbench_view() -> dict[str, object]:
        """Return only the selected profile's participant-visible projection."""
        launch = runtime.current_launch
        if launch is None:
            return {"profile": None, "run_id": None, "bookmarks": [], "mcp_servers": []}
        profile = profile_for(launch.profile)
        return {
            "profile": profile.profile_id.value,
            "run_id": launch.run_id,
            "bookmarks": list(profile.bookmark_refs),
            "mcp_servers": list(profile.server_ids),
        }

    @app.post("/workbench/profiles/{profile}", dependencies=session)
    async def select_profile(profile: str) -> dict[str, str]:
        """Switch profiles without accepting credentials, commands, or endpoints."""
        try:
            launch = runtime.switch(profile)
        except (ValueError, WorkbenchStateError):
            raise HTTPException(status_code=409, detail="Profile transition unavailable") from None
        return {"profile": launch.profile.value, "run_id": launch.run_id}

    return app
