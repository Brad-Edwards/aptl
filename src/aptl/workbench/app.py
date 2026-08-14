"""Dedicated participant browser surface for the in-appliance workbench."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from aptl.workbench.profiles import profile_for
from aptl.workbench.runtime import WorkbenchRuntime, WorkbenchStateError

ParticipantAuthorizer = Callable[[Request], bool]

_SCRIPT = """
const output = document.getElementById("output");
const status = document.getElementById("status");
const bookmarks = document.getElementById("bookmarks");
async function request(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {"Content-Type": "application/json"},
    ...options
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || "Workbench request failed");
  return body;
}
async function refresh() {
  const view = await request("/workbench");
  status.textContent = view.profile ? `Active profile: ${view.profile}` : "No active profile";
  bookmarks.replaceChildren(...view.bookmarks.map((bookmark) => {
    const link = document.createElement("a");
    link.href = bookmark.href;
    link.textContent = bookmark.label;
    return link;
  }));
}
document.querySelectorAll("[data-profile]").forEach((button) => {
  button.addEventListener("click", async () => {
    try {
      await request(`/workbench/profiles/${button.dataset.profile}`, {method: "POST"});
      await refresh();
    } catch (error) { output.textContent = error.message; }
  });
});
document.getElementById("send").addEventListener("click", async () => {
  const message = document.getElementById("message").value;
  try {
    const body = await request("/workbench/messages", {
      method: "POST",
      body: JSON.stringify({message})
    });
    output.textContent = body.response;
  } catch (error) { output.textContent = error.message; }
});
document.getElementById("close").addEventListener("click", async () => {
  try {
    await request("/workbench/profile", {method: "DELETE"});
    output.textContent = "";
    await refresh();
  } catch (error) { output.textContent = error.message; }
});
refresh().catch((error) => { output.textContent = error.message; });
""".strip()
_SCRIPT_HASH = base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()
_WORKBENCH_HTML = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>APTL Workbench</title></head>
<body><main>
<h1>APTL participant workbench</h1>
<p id="status">Loading profile…</p>
<nav aria-label="Profile selection">
<button type="button" data-profile="red">Red profile</button>
<button type="button" data-profile="blue">Blue profile</button>
<button type="button" id="close">Close profile</button>
</nav>
<nav id="bookmarks" aria-label="Participant bookmarks"></nav>
<label for="message">Message</label>
<textarea id="message" maxlength="16000"></textarea>
<button type="button" id="send">Send</button>
<pre id="output" aria-live="polite"></pre>
</main><script>{_SCRIPT}</script></body></html>"""

_BOOKMARKS = {
    "aptl-guide": {"label": "APTL guide", "href": "/guide/"},
    "kali-desktop": {"label": "Kali desktop", "href": "/desktop/kali/"},
    "soc-wazuh": {"label": "Wazuh", "href": "/soc/wazuh/"},
    "soc-thehive": {"label": "TheHive", "href": "/soc/thehive/"},
    "soc-misp": {"label": "MISP", "href": "/soc/misp/"},
    "soc-shuffle": {"label": "Shuffle", "href": "/soc/shuffle/"},
}


class ParticipantMessage(BaseModel):
    """The only participant-controlled input admitted to the agent."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=16_000)


def create_participant_workbench_app(
    runtime: WorkbenchRuntime, authorizer: ParticipantAuthorizer
) -> FastAPI:
    """Create a participant-only app, deliberately separate from operator APIs."""
    app = FastAPI(
        title="APTL Participant Workbench",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def require_participant_session(request: Request) -> None:
        """Reject requests that do not carry an admitted participant session."""
        if not authorizer(request):
            raise HTTPException(status_code=401, detail="Participant session required")

    session = [Depends(require_participant_session)]

    @app.get("/", response_class=HTMLResponse, dependencies=session)
    def workbench_page() -> HTMLResponse:
        """Serve the complete participant controls without an operator console."""
        return HTMLResponse(
            _WORKBENCH_HTML,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; "
                    f"script-src 'sha256-{_SCRIPT_HASH}'; "
                    "connect-src 'self'; object-src 'none'; base-uri 'none'"
                ),
                "Cache-Control": "no-store",
            },
        )

    @app.get("/workbench", dependencies=session)
    def workbench_view() -> dict[str, object]:
        """Return only the selected profile's participant-visible projection."""
        launch = runtime.current_launch
        if launch is None:
            return {"profile": None, "run_id": None, "bookmarks": [], "mcp_servers": []}
        profile = profile_for(launch.profile)
        return {
            "profile": profile.profile_id.value,
            "run_id": launch.run_id,
            "bookmarks": [_BOOKMARKS[ref] for ref in profile.bookmark_refs],
            "mcp_servers": list(profile.server_ids),
        }

    @app.post(
        "/workbench/profiles/{profile}",
        dependencies=session,
        responses={409: {"description": "Profile transition unavailable"}},
    )
    def select_profile(profile: str) -> dict[str, str]:
        """Switch profiles without accepting credentials, commands, or endpoints."""
        try:
            launch = runtime.switch(profile)
        except (ValueError, WorkbenchStateError):
            raise HTTPException(
                status_code=409, detail="Profile transition unavailable"
            ) from None
        return {"profile": launch.profile.value, "run_id": launch.run_id}

    @app.post(
        "/workbench/messages",
        dependencies=session,
        responses={409: {"description": "Agent request unavailable"}},
    )
    def send_message(message: ParticipantMessage) -> dict[str, str]:
        """Send one bounded prompt to the active selected profile."""
        try:
            response = runtime.respond(message.message)
        except WorkbenchStateError:
            raise HTTPException(
                status_code=409, detail="Agent request unavailable"
            ) from None
        return {"response": response}

    @app.delete(
        "/workbench/profile",
        dependencies=session,
        responses={409: {"description": "Profile teardown unavailable"}},
    )
    def close_profile() -> dict[str, str]:
        """Close the active profile and its local credential binding."""
        try:
            runtime.close()
        except WorkbenchStateError:
            raise HTTPException(
                status_code=409, detail="Profile teardown unavailable"
            ) from None
        return {"status": "closed"}

    return app
