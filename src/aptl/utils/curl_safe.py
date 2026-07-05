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
from typing import Any

from aptl.utils.logging import get_logger

log = get_logger("curl_safe")

DEFAULT_TIMEOUT_SECONDS = 30


def basic_auth_header(username: str, password: str) -> str:
    """Return an HTTP Basic ``Authorization`` header value for *username*/*password*.

    The returned ``"Basic <base64>"`` string is meant to be passed as
    ``auth_header`` to :func:`curl_json` / :func:`curl_status`, so the
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
    cmd: list[str] = ["curl", "-sf"]
    if insecure:
        cmd.append("-k")
    elif ca_cert_path:
        cmd += ["--cacert", ca_cert_path]
    if method:
        cmd += ["-X", method]
    cmd.append(url)
    cmd += ["-H", "Content-Type: application/json"]
    cmd += ["-H", "Accept: application/json"]

    header_path: str | None = None
    body_path: str | None = None
    parsed: Any | None = None
    try:
        if auth_header:
            header_path = _write_temp_0600("aptl-hdr-", "Authorization: " + auth_header + "\n")
            cmd += ["-H", "@" + header_path]

        if body is not None:
            body_path = _write_temp_0600("aptl-body-", json.dumps(body))
            cmd += ["-d", "@" + body_path]

        # A single return keeps the three failure modes (transport error,
        # non-zero exit, unparseable body) collapsing to the same ``None``
        # without a separate return per branch.
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
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
    finally:
        for path in (header_path, body_path):
            if path is None:
                continue
            try:
                os.unlink(path)
            except OSError:
                pass
    return parsed


def curl_status(
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    insecure: bool = False,
    ca_cert_path: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> int | None:
    """Issue an HTTP request via curl and return the response status code.

    Unlike :func:`curl_json`, this does not use ``-f``, so 4xx/5xx
    responses are reported with their real status rather than treated
    as errors — this is the classification probe used by callers that
    need to distinguish "not listening yet" from "listening but
    rejecting credentials".

    Basic-auth credentials, when provided via ``auth``, are written to
    a 0600 temp file as a base64-encoded ``Authorization: Basic`` header
    and passed to curl via ``-H @file`` rather than placed in argv
    (ADR-029) — unlike ``curl_json``'s ``-u user:pass``, which is
    visible in argv.

    Returns ``None`` for: subprocess startup failures, command
    timeouts, unparseable output, and curl's ``000`` sentinel (no HTTP
    response received at all). Never raises.
    """
    cmd: list[str] = ["curl", "-s", "-o", os.devnull, "-w", "%{http_code}"]
    if insecure:
        cmd.append("-k")
    elif ca_cert_path:
        cmd += ["--cacert", ca_cert_path]

    header_path: str | None = None
    try:
        if auth is not None:
            header_path = _write_temp_0600(
                "aptl-hdr-", f"Authorization: {basic_auth_header(*auth)}\n"
            )
            cmd += ["-H", "@" + header_path]

        cmd.append(url)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("curl_safe: subprocess failed: %s", exc.__class__.__name__)
            return None

        stdout = result.stdout.strip()
        if not stdout.isdigit():
            return None
        code = int(stdout)
        return code if code > 0 else None
    finally:
        if header_path is not None:
            try:
                os.unlink(header_path)
            except OSError:
                pass


def _write_temp_0600(prefix: str, content: str) -> str:
    """Write *content* to a 0600 temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix=prefix, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path
