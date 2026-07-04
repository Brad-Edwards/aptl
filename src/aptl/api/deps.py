"""Dependency injection and shared constants for the APTL API."""

import hmac
import importlib.resources
import os
from pathlib import Path
from typing import Annotated, Optional

from fastapi import Header, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator

from aptl.core.config import AptlConfig, find_config, load_config
from aptl.utils.placeholders import contains_placeholder

# UI-008a: cross-origin requests are gated by STRICT same-origin comparison
# (Origin == the request's own origin), not an allow-list. An allow-list bypass
# was a CSRF hole: a cookie is a host credential and SameSite ignores port, so a
# trusted dev origin (e.g. http://localhost:3000) bound by a malicious local
# process could drive cookie-authenticated mutating routes on the API port.
# Same-origin holds through the dev/preview proxies because they preserve the
# browser's Host (Caddy `header_up Host {host}`, vite `changeOrigin: false`).


class WebAuthSettings(BaseModel):
    """Runtime auth settings for the web control plane (ADR-039).

    Loaded once at app startup via :meth:`from_env`; never stored in
    ``AptlConfig`` or checked-in config per ADR-029.
    """

    model_config = ConfigDict(frozen=True)

    api_token: str

    @field_validator("api_token")
    @classmethod
    def _validate_token(cls, v: str) -> str:
        if not v:
            raise ValueError("APTL_API_TOKEN must not be empty")
        if contains_placeholder(v):
            raise ValueError(
                "APTL_API_TOKEN contains a placeholder value; set a real token"
            )
        return v

    @classmethod
    def from_env(cls) -> "WebAuthSettings":
        """Load and validate auth settings from environment variables.

        Raises :class:`ValueError` when ``APTL_API_TOKEN`` is missing, empty,
        or contains a placeholder sentinel.
        """
        raw = os.environ.get("APTL_API_TOKEN")
        if not raw:
            raise ValueError(
                "APTL_API_TOKEN is not set. "
                "Generate one with: "
                "python3 -c 'import secrets; print(secrets.token_hex(32))'"
            )
        return cls(api_token=raw)


# Module-level singleton.  None until load_web_auth() succeeds.
_WEB_AUTH: Optional[WebAuthSettings] = None


def load_web_auth() -> Optional[WebAuthSettings]:
    """Initialise the module-level auth singleton from the environment.

    Called from :func:`aptl.api.main.create_app`. On success, sets the global
    ``_WEB_AUTH`` and returns the new settings. On failure, logs a CRITICAL
    error and returns ``None`` so the app continues to start (all requests will
    return 401 until the process is restarted with a valid token).
    """
    import logging

    global _WEB_AUTH
    try:
        _WEB_AUTH = WebAuthSettings.from_env()
        return _WEB_AUTH
    except ValueError as exc:
        logging.getLogger("aptl.api").critical(
            "APTL_API_TOKEN not configured — all API requests will return 401: %s",
            exc,
        )
        _WEB_AUTH = None
        return None


def get_web_auth() -> WebAuthSettings:
    """FastAPI dependency that provides the current web auth settings.

    Raises ``HTTP 401`` when the API token was not configured at startup.
    Used by the terminal WebSocket handler (which cannot use :func:`verify_token`
    directly because WS auth uses the subprotocol field, not the Authorization
    header).
    """
    if _WEB_AUTH is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _WEB_AUTH


def verify_token(
    authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
) -> None:
    """FastAPI dependency: enforce bearer-token auth on every HTTP request.

    Uses constant-time comparison to prevent timing side-channels. Returns
    ``None`` on success; raises ``HTTP 401`` with a generic detail on any
    failure — the response does not indicate whether the token was missing,
    malformed, or wrong.
    """
    _unauthorized = HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if _WEB_AUTH is None:
        raise _unauthorized
    if not authorization or not authorization.startswith("Bearer "):
        raise _unauthorized
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token.encode(), _WEB_AUTH.api_token.encode()):
        raise _unauthorized


def verify_ws_token(sec_websocket_protocol: str, settings: WebAuthSettings) -> bool:
    """Extract and validate the bearer token from a ``Sec-WebSocket-Protocol`` header.

    Browsers cannot send ``Authorization`` headers on WebSocket upgrades, so the
    token is conveyed as ``aptl-token.<TOKEN>`` in the protocol field instead.
    Returns ``True`` only when the extracted token matches ``settings.api_token``
    via constant-time comparison.
    """
    prefix = "aptl-token."
    if not sec_websocket_protocol or not sec_websocket_protocol.startswith(prefix):
        return False
    candidate = sec_websocket_protocol[len(prefix):]
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode(), settings.api_token.encode())


def current_api_token() -> Optional[str]:
    """Return the live API token from the auth singleton, or ``None`` when unconfigured.

    Used by :class:`aptl.api.middleware.bff.BFFMiddleware` to inject a bearer
    token into first-party browser requests so the browser never needs to store
    the secret.
    """
    return _WEB_AUTH.api_token if _WEB_AUTH is not None else None


def get_web_asset_root(explicit: Optional[str] = None) -> Optional[Path]:
    """Resolve the web asset root directory.

    Precedence (first candidate with a valid ``index.html`` wins):

    1. *explicit* argument (passed directly, e.g. from ``--web-root`` CLI option)
    2. ``APTL_WEB_ROOT`` environment variable
    3. Packaged location: ``importlib.resources.files("aptl") / "web_static"``
    4. Repo-relative fallback: ``<repo_root>/web/build``

    Returns the resolved :class:`~pathlib.Path` when it exists and contains
    ``index.html``; otherwise returns ``None``. A ``None`` result is fatal for
    ``aptl web serve`` unless ``--api-only`` is passed (see the CLI): APTL ships
    clone-and-run, so the GUI is delivered either by the Docker ``aptl-web-ui``
    (Caddy) image or by a local ``cd web && npm run build`` that populates the
    repo-relative ``web/build``. Candidate 3 (``aptl/web_static``) is forward-
    compatible with a future combined-wheel delivery and resolves to nothing in
    the current models; see ``docs/specs/web-gui-design.md`` (asset delivery
    contract).
    """
    candidates: list[Path] = []

    if explicit:
        candidates.append(Path(explicit))

    env_root = os.environ.get("APTL_WEB_ROOT")
    if env_root:
        candidates.append(Path(env_root))

    try:
        pkg_ref = importlib.resources.files("aptl").joinpath("web_static")
        candidates.append(Path(str(pkg_ref)))
    except Exception:
        pass

    # Repo-relative fallback: this file lives at src/aptl/api/deps.py.
    # Walk up four levels: deps.py → api → aptl → src → repo root.
    repo_root = Path(__file__).parent.parent.parent.parent
    candidates.append(repo_root / "web" / "build")

    for candidate in candidates:
        try:
            if candidate.is_dir() and (candidate / "index.html").exists():
                return candidate
        except Exception:
            continue

    return None


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
        raise HTTPException(
            status_code=503,
            detail=f"Project directory does not exist: {p}",
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
