"""Browser session auth for the single-origin BFF (UI-008a / ADR-039).

A local web tool that grants code execution — terminals into lab containers,
lab lifecycle control — cannot treat loopback binding as authentication. Any
process on the host can reach a ``127.0.0.1`` port, and forgeable Fetch-Metadata
/ ``Origin`` headers are a CSRF-isolation signal, not a credential (a non-browser
client sets them at will). Authenticating the browser purely from those headers
would let any local process drive the control plane.

Following the established Jupyter model, the operator bootstraps a browser
session with a **launch token** printed to their terminal (a channel a sibling
process / other local user cannot read). Visiting the launch URL exchanges that
token for a session credential the browser holds and a sibling process cannot
forge or read.

**Two-factor session credential (closes the cross-port cookie leak).** A plain
cookie is necessary but *not sufficient* here: browser cookies are scoped by
host, not port, and ``SameSite`` treats ``127.0.0.1:<a>`` and ``127.0.0.1:<b>``
as the same site, so a cookie set for the APTL port is *also* sent to any other
loopback port. A sibling local process that lures the operator's browser to its
own port could read that cookie and replay it. So bearer injection requires BOTH
of two independent factors, and each defeats a different theft vector:

- an **HttpOnly, SameSite=Strict cookie** (:data:`SESSION_COOKIE`) — not readable
  by page JavaScript, so XSS cannot exfiltrate it; and
- a **header token** (:data:`SESSION_HEADER`) the SPA keeps in ``sessionStorage``
  (which is scoped by origin *including port* and is never auto-sent on
  navigation) and echoes on every ``/api/*`` fetch — so a sibling port can
  neither read it nor have it sent automatically.

The two values are independent HMAC tags derived from one per-process master
secret with domain separation, so possessing one (e.g. a cross-port-leaked
cookie) does not reveal the other (deriving it needs the master secret, which
never leaves the server). A cross-port attacker gets the cookie but not the
header; an XSS payload gets the header but not the cookie; neither alone
triggers injection. The forgeable Fetch-Metadata/Origin headers remain a CSRF
signal only, never a credential.

The master secret is per-serve-process. The ``aptl web serve`` CLI generates it
and exports it via the environment so all uvicorn workers derive the same tags
(module-level generation would differ per worker and reject each other's
credentials). The environment is readable only by the operator's own uid — the
same trust level as the cookie jar and SSH key — so it does not widen the
other-local-user threat this module defends against.
"""

import hashlib
import hmac
import os
import secrets
from typing import Optional

# Cookie the browser presents on same-origin /api/* calls after the handshake.
SESSION_COOKIE = "aptl_session"

# Header (lower-cased for ASGI/case-insensitive matching) carrying the
# port-scoped second factor the SPA reads from sessionStorage. The browser-side
# canonical send-name is ``X-APTL-Session``.
SESSION_HEADER = "x-aptl-session"

# Fragment parameter name the login redirect uses to hand the header token to the
# SPA (``/#<SESSION_HEADER_PARAM>=<token>``). The frontend mirrors this literal in
# ``web/src/lib/session.ts``; keep the two in sync.
SESSION_HEADER_PARAM = "aptl_session"

# Environment channel for sharing the per-process secrets across uvicorn workers.
LAUNCH_TOKEN_ENV = "APTL_WEB_LAUNCH_TOKEN"
SESSION_SECRET_ENV = "APTL_WEB_SESSION_SECRET"

# Domain-separation labels so the cookie tag and header tag derived from the one
# master secret are independent: knowing one never reveals the other.
_COOKIE_LABEL = b"aptl-session-cookie-v1"
_HEADER_LABEL = b"aptl-session-header-v1"

# Set once the launch token has been redeemed for a session cookie, so the
# bootstrap URL is genuinely one-time and cannot be replayed from terminal
# scrollback, container logs, or browser history. This is per-process state;
# `aptl web serve` therefore runs a single worker (the CLI warns otherwise),
# since the launch token and ticket stores are not shared across workers.
_launch_consumed: bool = False


def generate_secret() -> str:
    """Return a fresh URL-safe 256-bit secret."""
    return secrets.token_urlsafe(32)


def _get_or_create(env_name: str) -> str:
    """Return the secret in *env_name*, generating and storing one if absent.

    The ``aptl web serve`` CLI sets both env vars before starting uvicorn so
    every worker inherits the same value. When they are absent (tests, or a
    direct ``uvicorn`` invocation) a fresh value is generated once per process.
    """
    val = os.environ.get(env_name)
    if not val:
        val = generate_secret()
        os.environ[env_name] = val
    return val


def launch_token() -> str:
    """Return the current process's launch (bootstrap) token."""
    return _get_or_create(LAUNCH_TOKEN_ENV)


def _derive(label: bytes) -> str:
    """Derive a domain-separated HMAC tag from the per-process master secret.

    The master secret (``SESSION_SECRET_ENV``) is never used directly as a
    credential; the cookie and header tags are independent HMACs of distinct
    labels, so a leaked cookie tag does not reveal the header tag.
    """
    master = _get_or_create(SESSION_SECRET_ENV).encode()
    return hmac.new(master, label, hashlib.sha256).hexdigest()


def session_cookie_value() -> str:
    """Return the value to set in (and expect from) the session cookie."""
    return _derive(_COOKIE_LABEL)


def session_header_value() -> str:
    """Return the value the SPA must echo in the ``X-APTL-Session`` header.

    This is the port-scoped second factor: the SPA keeps it in ``sessionStorage``
    and sends it on every ``/api/*`` fetch. It is independent of the cookie tag,
    so a cross-port-leaked cookie cannot be combined with a forged header.
    """
    return _derive(_HEADER_LABEL)


def verify_launch_token(candidate: Optional[str]) -> bool:
    """Verify and CONSUME the launch token (one-time).

    Returns True at most once: a successful check marks the launch token consumed
    so a later replay of the bootstrap URL fails. Subsequent calls (and any call
    after consumption) return False. Constant-time comparison.
    """
    global _launch_consumed
    if _launch_consumed or not candidate:
        return False
    if hmac.compare_digest(candidate, launch_token()):
        _launch_consumed = True
        return True
    return False


def reset_launch_token_for_test() -> None:
    """Test-only: clear the consumed flag so a fresh launch can be exercised."""
    global _launch_consumed
    _launch_consumed = False


def verify_session_cookie(candidate: Optional[str]) -> bool:
    """Constant-time check that *candidate* is a valid session cookie value."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate, session_cookie_value())


def verify_session_header(candidate: Optional[str]) -> bool:
    """Constant-time check that *candidate* is a valid session header value."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate, session_header_value())
