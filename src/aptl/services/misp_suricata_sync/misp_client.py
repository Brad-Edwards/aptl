"""MISP REST client tailored for IOC sync.

Uses the shared :mod:`aptl.utils.curl_safe` helper for HTTP so the MISP
API key is passed via ``-H @file`` (out of argv) and TLS / timeout /
error semantics are identical to the rest of the lab's curl-based
clients. Auth is bare API key in the ``Authorization`` header, matching
the ``aptl-threatintel`` MCP convention.
"""

from __future__ import annotations

import time
from typing import Any

from aptl.services.misp_suricata_sync.config import ServiceConfig
from aptl.services.misp_suricata_sync.models import MispAttribute
from aptl.utils.curl_safe import curl_json as _curl_json
from aptl.utils.logging import get_logger

log = get_logger("misp_suricata_sync")

_HTTP_TIMEOUT_SECONDS = 30
_READY_POLL_SECONDS = 5


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
