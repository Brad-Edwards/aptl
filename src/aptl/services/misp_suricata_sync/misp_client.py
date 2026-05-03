"""MISP REST client tailored for IOC sync.

Reuses the curl-subprocess pattern established by ``aptl.core.collectors``:
a fault-tolerant ``_curl_json`` helper that returns ``None`` on any failure
instead of raising. Auth is bare API key in the ``Authorization`` header,
matching the existing ``aptl-threatintel`` MCP convention. The header is
written to a 0600 temp file and passed to curl via ``-H @file`` so the API
key never appears in argv (avoiding ``ps`` / ``/proc/*/cmdline`` leaks).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from typing import Any

from aptl.services.misp_suricata_sync.config import ServiceConfig
from aptl.services.misp_suricata_sync.models import MispAttribute
from aptl.utils.logging import get_logger

log = get_logger("misp_suricata_sync")

_HTTP_TIMEOUT_SECONDS = 30
_READY_POLL_SECONDS = 5


def _curl_json(
    url: str,
    *,
    auth_header: str,
    body: dict | None = None,
    insecure: bool,
    ca_cert_path: str | None = None,
    method: str = "POST",
    timeout: int = _HTTP_TIMEOUT_SECONDS,
) -> Any | None:
    """POST/GET JSON via curl; return parsed JSON or None on failure.

    Mirrors :func:`aptl.core.collectors._curl_json` but with the auth-header
    plumbing the MISP integration needs. The curl process never sees the
    parsed body, only its JSON form on stdin via ``-d``; the API key never
    appears on the command line.

    TLS posture (in priority order):
      - ``insecure=True`` → ``curl -k`` (skip verification entirely).
      - ``insecure=False`` and ``ca_cert_path`` set → ``curl --cacert <path>``
        (verify against the supplied CA bundle — this is the path SEC-006
        will exercise once the lab CA ships per #258).
      - ``insecure=False`` and no path → use curl's system trust store.
    """
    cmd = ["curl", "-sf", "-X", method, url]
    if insecure:
        cmd.insert(1, "-k")
    elif ca_cert_path:
        cmd += ["--cacert", ca_cert_path]

    # Write the Authorization header to a 0600 temp file and pass curl
    # `-H @file` so the API key never appears in argv. Same idea applies
    # to the request body — `-d @file` keeps it off the command line.
    fd, header_path = tempfile.mkstemp(prefix="aptl-misp-hdr-", text=True)
    body_path: str | None = None
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("Authorization: " + auth_header + "\n")
        cmd += ["-H", "@" + header_path]
        cmd += ["-H", "Content-Type: application/json"]
        cmd += ["-H", "Accept: application/json"]

        if body is not None:
            body_fd, body_path = tempfile.mkstemp(
                prefix="aptl-misp-body-", text=True
            )
            os.fchmod(body_fd, 0o600)
            with os.fdopen(body_fd, "w") as fh:
                fh.write(json.dumps(body))
            cmd += ["-d", "@" + body_path]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.warning("MISP curl failed: %s", exc.__class__.__name__)
            return None
    finally:
        try:
            os.unlink(header_path)
        except OSError:
            pass
        if body_path is not None:
            try:
                os.unlink(body_path)
            except OSError:
                pass

    if result.returncode != 0:
        log.warning(
            "MISP request to %s returned curl exit %d",
            url, result.returncode,
        )
        return None

    try:
        return json.loads(result.stdout)
    except ValueError:
        log.warning("MISP response from %s was not valid JSON", url)
        return None


class MispClient:
    """Polls MISP for IOC attributes carrying a configured tag."""

    def __init__(self, cfg: ServiceConfig) -> None:
        self._cfg = cfg

    def _ca_cert_str(self) -> str | None:
        path = self._cfg.misp_ca_cert_path
        return str(path) if path is not None else None

    def wait_for_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            data = _curl_json(
                f"{self._cfg.misp_url}/servers/getVersion",
                auth_header=self._cfg.misp_api_key,
                body=None,
                insecure=not self._cfg.misp_verify_ssl,
                ca_cert_path=self._ca_cert_str(),
                method="GET",
            )
            if isinstance(data, dict) and data.get("version"):
                log.info("MISP reachable; version=%s", data.get("version"))
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(_READY_POLL_SECONDS)

    def fetch_tagged_attributes(self) -> list[MispAttribute] | None:
        body = {
            "returnFormat": "json",
            "tags": [self._cfg.ioc_tag_filter],
        }
        data = _curl_json(
            f"{self._cfg.misp_url}/attributes/restSearch",
            auth_header=self._cfg.misp_api_key,
            body=body,
            insecure=not self._cfg.misp_verify_ssl,
            ca_cert_path=self._ca_cert_str(),
            method="POST",
        )
        if data is None:
            return None
        return self._parse_attributes(data)

    @staticmethod
    def _parse_attributes(data: Any) -> list[MispAttribute] | None:
        """Return parsed attributes, or ``None`` if the envelope is malformed.

        Distinguishing ``None`` (envelope drift / error response) from ``[]``
        (legitimate empty IOC set) is critical for the MISP-down preservation
        invariant: ``None`` causes :func:`run_once` to skip the write/reload
        cycle and keep the existing rule file, while ``[]`` produces a valid
        zero-rule render.
        """
        if not isinstance(data, dict):
            return None
        response = data.get("response")
        if not isinstance(response, dict):
            return None
        raw = response.get("Attribute")
        if not isinstance(raw, list):
            return None

        attrs: list[MispAttribute] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            type_ = item.get("type")
            value = item.get("value")
            if not isinstance(type_, str) or not isinstance(value, str):
                continue
            event_id = item.get("event_id")
            event_id_str = (
                str(event_id) if isinstance(event_id, (str, int)) else None
            )
            try:
                attrs.append(
                    MispAttribute(type=type_, value=value, event_id=event_id_str)
                )
            except ValueError:
                continue
        return attrs
