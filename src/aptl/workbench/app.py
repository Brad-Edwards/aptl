"""Dedicated participant browser surface for the in-appliance workbench."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from aptl.workbench.profiles import profile_for
from aptl.workbench.runtime import WorkbenchRuntime, WorkbenchStateError


@dataclass(frozen=True)
class BrowserPrincipal:
    """Identity and roles supplied by the trusted session verifier."""

    caller_id: str
    profiles: tuple[Literal["red", "blue", "guided-blue"], ...]


ParticipantAuthorizer = Callable[[Request], BrowserPrincipal | None]

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
  document.querySelectorAll("[data-profile]").forEach(button => {
    button.hidden = !view.allowed_profiles.includes(button.dataset.profile);
  });
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
    "kali-desktop": {"label": "Kali terminal", "href": "/desktop/kali/"},
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
    runtime: WorkbenchRuntime,
    authorizer: ParticipantAuthorizer,
    *,
    bookmark_urls: dict[str, str] | None = None,
) -> FastAPI:
    """Create a participant-only app, deliberately separate from operator APIs."""
    app = FastAPI(
        title="APTL Participant Workbench",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        responses={401: {"description": "Participant session required"}},
    )

    bookmarks = {
        key: {**value, "href": (bookmark_urls or {}).get(key, value["href"])}
        for key, value in _BOOKMARKS.items()
    }
    access = _WorkbenchAccess(runtime, authorizer)
    _attach_views(app, runtime, access, bookmarks)
    _attach_commands(app, runtime, access)
    return app


def _principal_bookmarks(principal: BrowserPrincipal) -> tuple[str, ...]:
    """Collect the browser surfaces authorized for this participant."""
    return tuple(
        dict.fromkeys(
            ref
            for role in principal.profiles
            for ref in profile_for(role).bookmark_refs
        )
    )


def _require_profile(principal: BrowserPrincipal, profile: str) -> None:
    """Reject profile selections outside the admitted participant roles."""
    if profile not in principal.profiles:
        raise HTTPException(status_code=403, detail="Profile is not authorized")


class _WorkbenchAccess:
    """Serialize profile changes and retain the current participant owner."""

    def __init__(
        self, runtime: WorkbenchRuntime, authorizer: ParticipantAuthorizer
    ) -> None:
        self.runtime = runtime
        self.authorizer = authorizer
        self.owner: str | None = None
        self.guard = RLock()

    def require_participant_session(self, request: Request) -> BrowserPrincipal:
        """Require a named participant with at least one admitted role."""
        principal = self.authorizer(request)
        if (
            not isinstance(principal, BrowserPrincipal)
            or not principal.caller_id
            or not principal.profiles
        ):
            raise HTTPException(status_code=401, detail="Participant session required")
        return principal

    def require_owner(self, principal: BrowserPrincipal) -> None:
        """Require the caller to own and retain access to the active profile."""
        if self.owner is not None and self.owner != principal.caller_id:
            raise HTTPException(
                status_code=403, detail="Profile belongs to another caller"
            )
        launch = self.runtime.current_launch
        if launch is not None and launch.profile.value not in principal.profiles:
            raise HTTPException(status_code=403, detail="Profile is not authorized")


def _attach_views(
    app: FastAPI,
    runtime: WorkbenchRuntime,
    access: _WorkbenchAccess,
    bookmarks: dict[str, dict[str, str]],
) -> None:
    """Mount the participant controls and authorized state projection."""
    session = [Depends(access.require_participant_session)]

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

    @app.get(
        "/workbench",
        dependencies=session,
        responses={403: {"description": "Profile is not authorized"}},
    )
    def workbench_view(
        principal: BrowserPrincipal = Depends(access.require_participant_session),
    ) -> dict[str, object]:
        """Return only the selected profile's participant-visible projection."""
        access.require_owner(principal)
        launch = runtime.current_launch
        if launch is None:
            refs = _principal_bookmarks(principal)
            return {
                "profile": None,
                "run_id": None,
                "bookmarks": [bookmarks[ref] for ref in refs],
                "mcp_servers": [],
                "allowed_profiles": list(principal.profiles),
            }
        profile = profile_for(launch.profile)
        return {
            "allowed_profiles": list(principal.profiles),
            "profile": profile.profile_id.value,
            "run_id": launch.run_id,
            "bookmarks": [bookmarks[ref] for ref in profile.bookmark_refs],
            "mcp_servers": list(profile.server_ids),
        }


def _attach_commands(
    app: FastAPI, runtime: WorkbenchRuntime, access: _WorkbenchAccess
) -> None:
    """Mount owner-checked profile and agent operations under one lock."""
    session = [Depends(access.require_participant_session)]

    @app.post(
        "/workbench/profiles/{profile}",
        dependencies=session,
        responses={
            403: {"description": "Profile is not authorized"},
            409: {"description": "Profile transition unavailable"},
        },
    )
    def select_profile(
        profile: str,
        principal: BrowserPrincipal = Depends(access.require_participant_session),
    ) -> dict[str, str]:
        """Switch profiles without accepting credentials, commands, or endpoints."""
        _require_profile(principal, profile)
        try:
            with access.guard:
                access.require_owner(principal)
                launch = runtime.switch(profile)
                access.owner = principal.caller_id
        except (ValueError, WorkbenchStateError):
            raise HTTPException(
                status_code=409, detail="Profile transition unavailable"
            ) from None
        return {"profile": launch.profile.value, "run_id": launch.run_id}

    @app.post(
        "/workbench/messages",
        dependencies=session,
        responses={
            403: {"description": "Profile is not authorized"},
            409: {"description": "Agent request unavailable"},
        },
    )
    def send_message(
        message: ParticipantMessage,
        principal: BrowserPrincipal = Depends(access.require_participant_session),
    ) -> dict[str, str]:
        """Send one bounded prompt to the active selected profile."""
        try:
            with access.guard:
                access.require_owner(principal)
                response = runtime.respond(message.message)
        except WorkbenchStateError:
            raise HTTPException(
                status_code=409, detail="Agent request unavailable"
            ) from None
        return {"response": response}

    @app.delete(
        "/workbench/profile",
        dependencies=session,
        responses={
            403: {"description": "Profile is not authorized"},
            409: {"description": "Profile teardown unavailable"},
        },
    )
    def close_profile(
        principal: BrowserPrincipal = Depends(access.require_participant_session),
    ) -> dict[str, str]:
        """Close the active profile and its local credential binding."""
        try:
            with access.guard:
                access.require_owner(principal)
                runtime.close()
                access.owner = None
        except WorkbenchStateError:
            raise HTTPException(
                status_code=409, detail="Profile teardown unavailable"
            ) from None
        return {"status": "closed"}
