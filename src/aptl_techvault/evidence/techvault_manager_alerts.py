"""TechVault-owned native reader for the declared Wazuh manager alert log."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from aptl_techvault.evidence.techvault_native_support import (
    MAX_SOURCE_BYTES,
    find_node,
    inside_window,
)

_TIMESTAMP_FIELD = "@timestamp"
_MANAGER_ALERT_PATH = "/var/ossec/logs/alerts/alerts.json"


@dataclass(frozen=True)
class WazuhManagerAlertRead:
    """Typed result from the single admitted manager-alert source operation."""

    records: tuple[Mapping[str, object], ...] = ()
    loss_category: str | None = None

    @property
    def complete(self) -> bool:
        """Return whether the declared source was read and parsed successfully."""

        return self.loss_category is None


def _read_tail(backend: object, container: str) -> tuple[str, str | None]:
    """Read the bounded manager alert suffix and classify transport loss."""

    try:
        result = backend.container_exec(
            container,
            ["tail", "-c", str(MAX_SOURCE_BYTES), _MANAGER_ALERT_PATH],
            timeout=30,
        )
    # broad-except: backend transports expose implementation-specific failures.
    except Exception:
        return "", "source-exec-failed"
    loss = None
    if result.returncode != 0:
        loss = "source-command-failed"
    elif len(result.stdout.encode()) > MAX_SOURCE_BYTES:
        loss = "source-output-oversized"
    return result.stdout, loss


def _parse_alerts(raw: str, start_iso: str, end_iso: str) -> WazuhManagerAlertRead:
    """Parse a bounded NDJSON suffix, tolerating only its partial first line."""

    normalized: list[Mapping[str, object]] = []
    loss: str | None = None
    for index, line in enumerate(raw.splitlines()):
        try:
            source = json.loads(line)
        except json.JSONDecodeError:
            if index != 0:
                loss = "source-ndjson-malformed"
                break
            continue
        if not isinstance(source, Mapping):
            loss = "source-record-invalid"
            break
        item = dict(source)
        item["timestamp"] = source.get("timestamp", source.get(_TIMESTAMP_FIELD))
        if inside_window(item["timestamp"], start_iso, end_iso):
            normalized.append(item)
    records = tuple(normalized[:256]) if loss is None else ()
    return WazuhManagerAlertRead(records=records, loss_category=loss)


def read_wazuh_manager_alerts(
    backend: object,
    realization: object,
    start_iso: str,
    end_iso: str,
) -> WazuhManagerAlertRead:
    """Read bounded NDJSON from the realization-declared manager source."""

    manager = find_node(realization, "wazuh-manager")
    container = getattr(manager, "container_name", None)
    result = WazuhManagerAlertRead(loss_category="declared-manager-unavailable")
    if isinstance(container, str) and container:
        raw, loss = _read_tail(backend, container)
        result = (
            WazuhManagerAlertRead(loss_category=loss)
            if loss is not None
            else _parse_alerts(raw, start_iso, end_iso)
        )
    return result


__all__ = ["WazuhManagerAlertRead", "read_wazuh_manager_alerts"]
