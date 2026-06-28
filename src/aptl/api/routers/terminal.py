"""WebSocket terminal endpoint for container SSH access."""

import asyncio
import json
import secrets
import time
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import asyncssh
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from aptl.api.deps import (
    WebAuthSettings,
    get_project_dir,
    get_web_auth,
    verify_ws_token,
)
from aptl.core.endpoints import TERMINAL_CONTAINER_NAMES
from aptl.core.host_keys import known_hosts_path
from aptl.core.lab import lab_status, lab_terminal_ssh_endpoints
from aptl.core.snapshot import SSHEndpoint
from aptl.core.ssh import _KEY_NAME
from aptl.utils.logging import get_logger

log = get_logger("api.terminal")

router = APIRouter(tags=["terminal"])

# ---------------------------------------------------------------------------
# Single-use terminal ticket store
# ---------------------------------------------------------------------------

_TICKET_TTL: float = 30.0
_WS_TICKET_PREFIX = "aptl-token."


class _TicketStore:
    """In-memory single-use ticket store with monotonic-clock TTL.

    Each ticket is a ``secrets.token_urlsafe(32)`` string valid for at most
    one WebSocket authentication within *ttl* seconds of issuance.  Expired
    and consumed tickets are pruned on every access.
    """

    def __init__(self, ttl: float = _TICKET_TTL) -> None:
        self._ttl: float = ttl
        # ticket → expiry timestamp (time.monotonic())
        self._tickets: dict[str, float] = {}

    def issue(self) -> str:
        """Issue a new single-use ticket and return its opaque value."""
        self._prune()
        ticket = secrets.token_urlsafe(32)
        self._tickets[ticket] = time.monotonic() + self._ttl
        return ticket

    def consume(self, ticket: str) -> bool:
        """Consume *ticket*.

        Returns ``True`` exactly once for a valid, unexpired ticket.
        Returns ``False`` for unknown, already-consumed, or expired tickets.
        """
        self._prune()
        if ticket not in self._tickets:
            return False
        del self._tickets[ticket]
        return True

    def _prune(self) -> None:
        """Remove all expired tickets from the store."""
        now = time.monotonic()
        expired = [t for t, exp in self._tickets.items() if exp <= now]
        for t in expired:
            del self._tickets[t]


# Module-level store; tests may reset ``_ticket_store._tickets`` directly.
_ticket_store = _TicketStore()


def issue_ticket() -> str:
    """Issue a new single-use terminal WebSocket ticket."""
    return _ticket_store.issue()


def consume_ticket(ticket: str) -> bool:
    """Consume *ticket*.  Returns ``True`` once; ``False`` thereafter."""
    return _ticket_store.consume(ticket)


def verify_ws_ticket(sec_websocket_protocol: str) -> bool:
    """Extract and consume a ticket from a ``Sec-WebSocket-Protocol`` value.

    The ticket is conveyed as ``aptl-token.<TICKET>`` — the same prefix used
    by :func:`aptl.api.deps.verify_ws_token` for bearer tokens.  Returns
    ``True`` exactly once for a valid, unexpired ticket; ``False`` otherwise.
    """
    if not sec_websocket_protocol or not sec_websocket_protocol.startswith(
        _WS_TICKET_PREFIX
    ):
        return False
    candidate = sec_websocket_protocol[len(_WS_TICKET_PREFIX):]
    if not candidate:
        return False
    return consume_ticket(candidate)


def _get_key_path() -> Path:
    """Resolve the SSH private key path."""
    return Path.home() / ".ssh" / _KEY_NAME


async def _relay_ssh_to_ws(
    process: asyncssh.SSHClientProcess,
    websocket: WebSocket,
) -> None:
    """Read SSH stdout and forward to WebSocket."""
    try:
        while True:
            data = await process.stdout.read(4096)
            if not data:
                break
            await websocket.send_json({"type": "stdout", "data": data})
    except (asyncio.CancelledError, WebSocketDisconnect):
        pass


async def _relay_ws_to_ssh(
    websocket: WebSocket,
    process: asyncssh.SSHClientProcess,
) -> None:
    """Read WebSocket messages and forward to SSH stdin or handle resize."""
    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type")
            if msg_type == "stdin":
                process.stdin.write(msg.get("data", ""))
            elif msg_type == "resize":
                cols = max(1, min(msg.get("cols", 80), 500))
                rows = max(1, min(msg.get("rows", 24), 200))
                process.change_terminal_size(cols, rows)
    except (asyncio.CancelledError, WebSocketDisconnect):
        pass
    except json.JSONDecodeError:
        log.debug("Malformed WebSocket message, ignoring")


def _sanitize(value: str) -> str:
    """Strip CR/LF from *value* to defend against log injection (S5145)."""
    return value.replace("\r", "").replace("\n", "")


def _ws_origin_allowed(websocket: WebSocket) -> bool:
    """Return True when the WebSocket upgrade is strictly same-origin.

    The upgrade is trusted only when its ``Origin`` host matches the request's
    own ``Host`` — the shipped ``aptl web serve`` single-origin model, and the
    dev/preview profile too because the proxy preserves the browser's Host
    (Caddy ``header_up Host {host}``). There is no allow-list bypass: matching a
    configured origin by name would let a malicious local process on a trusted
    dev port drive the terminal (the same CSRF hole closed for HTTP). A missing
    Origin is rejected — ``Origin`` is a browser-set defence, not a credential,
    but its absence on a browser upgrade is anomalous.
    """
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not origin or not host:
        return False
    return urlsplit(origin).netloc == host


class _TerminalReject(Exception):
    """Internal signal that a pre-dial gate has closed the WebSocket.

    Each validation gate performs its own accept/send/close I/O and then
    raises this so the resolver funnels through a single success return
    (keeping the cyclomatic return count low) while the caller simply
    stops.
    """


async def _resolve_terminal_target(
    websocket: WebSocket,
    container: str,
    project_dir: Path,
    auth: WebAuthSettings,
) -> tuple[SSHEndpoint, Path]:
    """Run the pre-dial validation gates for a terminal connection.

    Performs the bearer-token, origin, container-allowlist, lab-running,
    endpoint, and host-key-pin checks. Returns the resolved endpoint and
    known_hosts path on success, or raises :class:`_TerminalReject` after
    closing the WebSocket if any gate rejects the connection. ``container``
    is the original path param (used for the allowlist check); callers must
    sanitize it before logging.
    """
    safe_container = _sanitize(container)

    # Verify bearer token OR single-use ticket before the handshake (ADR-039).
    # Browser clients receive a ticket from GET /api/terminal/ticket (which is
    # injected with the server bearer by BFF middleware) and convey it as the
    # Sec-WebSocket-Protocol subprotocol.  Direct API clients use a real token.
    protocol = websocket.headers.get("sec-websocket-protocol", "")
    if not (verify_ws_token(protocol, auth) or verify_ws_ticket(protocol)):
        await websocket.close(code=1008, reason="Unauthorized")
        log.warning("Rejected WebSocket: invalid or missing auth token or ticket")
        raise _TerminalReject

    # Reject cross-origin WebSocket connections.
    # CORS middleware does NOT protect WebSocket upgrades — browsers send
    # them cross-origin without preflight. Without this check, any website
    # the user visits could open a shell on lab containers.
    if not _ws_origin_allowed(websocket):
        origin = websocket.headers.get("origin", "")
        await websocket.close(code=1008, reason="Origin not allowed")
        log.warning("Rejected WebSocket from disallowed origin: %s", origin)
        raise _TerminalReject

    # Validate container name against the canonical registry projection
    # (ADR-040) — a cheap reject before touching runtime inventory.
    if container not in TERMINAL_CONTAINER_NAMES:
        await websocket.accept()
        await websocket.close(code=1008, reason="Unknown container")
        log.warning("Rejected terminal connection for unknown container")
        raise _TerminalReject

    # Check lab is running
    status = await asyncio.to_thread(lab_status, project_dir=project_dir)
    if not status.running:
        await websocket.accept()
        await websocket.send_json(
            {"type": "error", "message": "Lab is not running"}
        )
        await websocket.close(code=1008, reason="Lab not running")
        log.warning("Rejected terminal connection: lab not running")
        raise _TerminalReject

    await websocket.accept()

    # Endpoint identity gate (ADR-040): host/user/port come from the
    # canonical endpoint registry projected over runtime inventory
    # (container IP over the bridge, issue #293), not a hardcoded
    # localhost map. A target that is not currently running fails closed.
    endpoints = await asyncio.to_thread(
        lab_terminal_ssh_endpoints, project_dir
    )
    endpoint = endpoints.get(container)
    if endpoint is None:
        await websocket.send_json(
            {"type": "error", "message": "Container not available"}
        )
        await websocket.close(code=1008, reason="Container not available")
        log.warning("Terminal target not available in runtime inventory")
        raise _TerminalReject

    # SSH trust gate (ADR-040): verify the server host key against the
    # lab-start-pinned known_hosts file. A missing pin fails closed
    # rather than silently disabling verification.
    kh_path = known_hosts_path(project_dir)
    if not kh_path.exists():
        await websocket.send_json(
            {
                "type": "error",
                "message": "SSH host keys not pinned; restart the lab",
            }
        )
        await websocket.close(code=1008, reason="Host keys not pinned")
        log.warning("Terminal refused: no pinned known_hosts at %s", kh_path)
        raise _TerminalReject

    log.info("Terminal WebSocket accepted for %s", safe_container)
    return endpoint, kh_path


@router.get("/terminal/ticket")
async def terminal_ticket() -> dict[str, object]:
    """Issue a single-use WebSocket authentication ticket.

    The ticket is valid for :data:`_TICKET_TTL` seconds and may be used exactly
    once as the ``Sec-WebSocket-Protocol`` subprotocol value on a subsequent
    ``/api/terminal/ws/{container}`` WebSocket connection.

    This endpoint is auth-gated by ``Depends(verify_token)`` via the router's
    ``dependencies`` list in :func:`aptl.api.main.create_app`.  Same-origin
    browser calls receive a bearer token injection from the BFF middleware, so
    no explicit ``Authorization`` header is required on the browser side.
    """
    return {"ticket": issue_ticket(), "expires_in": int(_TICKET_TTL)}


@router.websocket("/terminal/ws/{container}")
async def terminal_ws(
    websocket: WebSocket,
    container: str,
    project_dir: Path = Depends(get_project_dir),
    auth: Annotated[WebAuthSettings, Depends(get_web_auth)] = ...,  # type: ignore[assignment]
) -> None:
    """WebSocket endpoint for interactive terminal sessions.

    Opens an SSH PTY connection to the specified container and relays
    stdin/stdout between the WebSocket and the SSH process.
    """
    safe_container = _sanitize(container)

    try:
        endpoint, kh_path = await _resolve_terminal_target(
            websocket, container, project_dir, auth
        )
    except _TerminalReject:
        return

    key_path = _get_key_path()

    conn = None
    try:
        conn = await asyncssh.connect(
            host=endpoint.host,
            port=endpoint.port,
            username=endpoint.user,
            client_keys=[str(key_path)],
            known_hosts=str(kh_path),
        )
        process = await conn.create_process(
            term_type="xterm-256color",
            term_size=(80, 24),
        )

        await asyncio.gather(
            _relay_ssh_to_ws(process, websocket),
            _relay_ws_to_ssh(websocket, process),
        )
    except asyncssh.Error as exc:
        log.exception("SSH connection error for %s: %s", safe_container, exc)
        try:
            await websocket.send_json(
                {"type": "error", "message": "SSH connection failed"}
            )
        except Exception:
            pass
    except WebSocketDisconnect:
        log.info("Terminal WebSocket disconnected from %s", safe_container)
    finally:
        if conn is not None:
            conn.close()
        log.info("Terminal session cleaned up for %s", safe_container)
