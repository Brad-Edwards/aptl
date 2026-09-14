"""Secret-safe curl JSON wrapper.

Single shared helper used by every component that talks to a SOC tool's
REST API via curl-subprocess (collectors, the MISP→Suricata sync service,
future services). Centralising it keeps timeout/TLS/error handling
uniform and prevents per-component drift in how secrets are passed to
curl.

Secret-safety:
  * The ``Authorization: <token>`` header — when provided via
    ``auth_header`` — is written to a 0600 temp file and passed to curl
    via ``-H @file`` rather than placed in argv. ``ps`` and
    ``/proc/<pid>/cmdline`` therefore cannot recover the token.
  * Basic auth has no argv path here: build the header value with
    :func:`basic_auth_header` and pass it as ``auth_header`` so the
    credentials travel through the same 0600 temp file (ADR-029), never
    ``-u user:pass`` in argv.
  * The request body, when provided, is written to a second 0600 temp
    file and passed via ``-d @file`` so any payload secret stays out of
    argv.

Failure handling: every error path returns ``None`` and never raises,
matching the fault-tolerant collector pattern.

TLS posture (priority order):
  1. ``insecure=True`` → ``curl -k`` (skip verification entirely).
  2. ``insecure=False`` and ``ca_cert_path`` set → ``curl --cacert <path>``.
  3. ``insecure=False`` and no path → curl's system trust store.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from aptl.utils.logging import get_logger

log = get_logger("curl_safe")

DEFAULT_TIMEOUT_SECONDS = 30

_JSON_HEADERS = (
    "-H",
    "Content-Type: application/json",
    "-H",
    "Accept: application/json",
)

#: curl result codes that mean no HTTP response arrived, by portable meaning.
#: Only the numeric code is classified; curl's TLS-library-specific stderr is
#: never parsed. Exit 35 names the incomplete handshake it proves and nothing
#: more: Docker's published-port proxy produces it for a container port with
#: no listener behind it, as does a genuine TLS negotiation failure.
_TRANSPORT_CATEGORIES = {
    7: "connection_refused",
    28: "timeout",
    35: "tls_handshake",
    52: "empty_reply",
    56: "connection_reset",
}


def basic_auth_header(username: str, password: str) -> str:
    """Return an HTTP Basic ``Authorization`` header value for *username*/*password*.

    The returned ``"Basic <base64>"`` string is meant to be passed as
    ``auth_header`` to :func:`curl_json` / :func:`curl_request`, so the
    credentials travel through a 0600 temp header file instead of curl's
    argv-visible ``-u user:pass`` (ADR-029).
    """
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def curl_json(
    url: str,
    *,
    auth_header: str | None = None,
    body: dict | list | None = None,
    insecure: bool = False,
    ca_cert_path: str | None = None,
    method: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Any | None:
    """Issue an HTTP request via curl and return parsed JSON, or ``None``.

    Basic auth callers pass ``auth_header=basic_auth_header(user, pass)``
    so the credentials go through the 0600 temp header file, never argv
    (ADR-029).

    Returns ``None`` for: subprocess startup failures, command timeouts,
    non-zero curl exit codes (transport errors, HTTP >= 400), and JSON
    parse errors. Never raises.
    """
    cmd: list[str] = ["curl", "-sf", *_tls_args(insecure, ca_cert_path)]
    if method:
        cmd += ["-X", method]
    cmd.append(url)
    cmd += _JSON_HEADERS

    parsed: Any | None = None
    with _secret_file_args(auth_header, body) as secret_args:
        # A single return keeps the three failure modes (transport error,
        # non-zero exit, unparseable body) collapsing to the same ``None``
        # without a separate return per branch.
        try:
            result = _run_curl([*cmd, *secret_args], timeout)
            if result.returncode != 0:
                log.warning(
                    "curl_safe: curl exit %d for %s", result.returncode, url
                )
            else:
                parsed = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("curl_safe: subprocess failed: %s", exc.__class__.__name__)
        except ValueError:
            log.warning("curl_safe: response from %s was not valid JSON", url)
    return parsed


@dataclass(frozen=True)
class CurlOutcome:
    """Secret-free, classified outcome of one :func:`curl_request`.

    Carries only what a caller needs to decide policy: curl's numeric exit
    (``None`` when curl never completed), the HTTP status (``None`` when no
    HTTP response arrived), and the parsed JSON payload. The payload may hold
    a token, so it is excluded from ``repr``; the URL, stdout, stderr, headers
    and temp-file paths are never retained.
    """

    exit_code: int | None
    http_status: int | None
    payload: Any | None = field(default=None, repr=False)
    failure: str | None = None

    @property
    def category(self) -> str:
        """Return ``http_response`` or the normalized transport failure."""

        if self.http_status is not None:
            return "http_response"
        if self.failure is not None:
            return self.failure
        return _TRANSPORT_CATEGORIES.get(self.exit_code, "curl_error")


def curl_request(
    url: str,
    *,
    auth_header: str | None = None,
    body: dict | list | None = None,
    insecure: bool = False,
    ca_cert_path: str | None = None,
    method: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> CurlOutcome:
    """Issue one HTTP request via curl and return its classified outcome.

    The classification seam for callers that poll: unlike :func:`curl_json`
    it keeps transport failure (curl exit, no HTTP status) apart from an HTTP
    answer of any status, and it never logs at warning level, because only
    the polling owner knows whether a failure is expected warm-up or a
    terminal condition. Secrets use the same 0600 temp files as
    :func:`curl_json` (ADR-029). Never raises for transport problems.
    """

    cmd: list[str] = ["curl", "-s", "-w", "\n%{http_code}"]
    cmd += _tls_args(insecure, ca_cert_path)
    if method:
        cmd += ["-X", method]
    cmd.append(url)
    cmd += _JSON_HEADERS

    with _secret_file_args(auth_header, body) as secret_args:
        try:
            result = _run_curl([*cmd, *secret_args], timeout)
        except subprocess.TimeoutExpired:
            return CurlOutcome(None, None, failure="request_timeout")
        except OSError:
            return CurlOutcome(None, None, failure="curl_unavailable")

    text, _, code = result.stdout.rpartition("\n")
    status = int(code) if code.isdigit() and int(code) > 0 else None
    payload: Any | None = None
    if status is not None:
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
    return CurlOutcome(result.returncode, status, payload)


def _tls_args(insecure: bool, ca_cert_path: str | None) -> list[str]:
    """Return curl's TLS arguments in the module's documented priority order."""

    if insecure:
        return ["-k"]
    if ca_cert_path:
        return ["--cacert", ca_cert_path]
    return []


@contextmanager
def _secret_file_args(
    auth_header: str | None,
    body: dict | list | None,
) -> Iterator[list[str]]:
    """Yield curl args that read the auth header and body from 0600 files.

    The files are removed when the block exits, however it exits, so a
    secret never outlives the request (ADR-029).
    """

    paths: list[str] = []
    args: list[str] = []
    try:
        if auth_header:
            paths.append(
                _write_temp_0600("aptl-hdr-", "Authorization: " + auth_header + "\n")
            )
            args += ["-H", "@" + paths[-1]]
        if body is not None:
            paths.append(_write_temp_0600("aptl-body-", json.dumps(body)))
            args += ["-d", "@" + paths[-1]]
        yield args
    finally:
        for path in paths:
            try:
                os.unlink(path)
            except OSError:
                pass


def _run_curl(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a list-form curl command with the module's fixed capture settings."""

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _write_temp_0600(prefix: str, content: str) -> str:
    """Write *content* to a 0600 temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix=prefix, text=True)
    try:
        # Restrict to owner before writing the sensitive header. os.fchmod
        # is POSIX-only; on Windows fall back to a path-based chmod (mkstemp
        # already creates the file in the user's private temp dir with an
        # owner-scoped ACL), so this never breaks the control plane there.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path
