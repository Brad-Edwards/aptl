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
  * Basic auth (``auth=(user, pass)``) goes through ``-u user:pass`` and
    is visible in argv. Use ``auth_header`` for high-value tokens.
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

import json
import os
import subprocess
import tempfile
from typing import Any

from aptl.utils.logging import get_logger

log = get_logger("curl_safe")

DEFAULT_TIMEOUT_SECONDS = 30


def curl_json(
    url: str,
    *,
    auth: tuple[str, str] | None = None,
    auth_header: str | None = None,
    body: dict | list | None = None,
    insecure: bool = False,
    ca_cert_path: str | None = None,
    method: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Any | None:
    """Issue an HTTP request via curl and return parsed JSON, or ``None``.

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
    if auth is not None:
        cmd += ["-u", f"{auth[0]}:{auth[1]}"]
    cmd += ["-H", "Content-Type: application/json"]
    cmd += ["-H", "Accept: application/json"]

    header_path: str | None = None
    body_path: str | None = None
    try:
        if auth_header:
            header_path = _write_temp_0600("aptl-hdr-", "Authorization: " + auth_header + "\n")
            cmd += ["-H", "@" + header_path]

        if body is not None:
            body_path = _write_temp_0600("aptl-body-", json.dumps(body))
            cmd += ["-d", "@" + body_path]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("curl_safe: subprocess failed: %s", exc.__class__.__name__)
            return None

        if result.returncode != 0:
            log.warning(
                "curl_safe: curl exit %d for %s",
                result.returncode, url,
            )
            return None

        try:
            return json.loads(result.stdout)
        except ValueError:
            log.warning("curl_safe: response from %s was not valid JSON", url)
            return None
    finally:
        for path in (header_path, body_path):
            if path is None:
                continue
            try:
                os.unlink(path)
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
