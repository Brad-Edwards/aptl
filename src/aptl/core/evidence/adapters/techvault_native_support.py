"""Pure support functions for TechVault's native evidence owner."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

from aptl.core.deployment._compose_stateful_model import artifact_source_path

MAX_SOURCE_BYTES = 2 * 1024 * 1024
UTC_OFFSET = "+00:00"


def utc_iso_now() -> str:
    """Return the current UTC instant in canonical ISO form."""

    return datetime.now(timezone.utc).isoformat().replace(UTC_OFFSET, "Z")


def bounded(value: object) -> bool:
    """Return whether a JSON-compatible value fits the source byte limit."""

    try:
        encoded = json.dumps(value, separators=(",", ":"), default=str).encode()
    except (TypeError, ValueError, RecursionError):
        return False
    return len(encoded) <= MAX_SOURCE_BYTES


def find_node(realization: object, name: str) -> object | None:
    """Find one named node in a deployment realization."""

    return next(
        (
            item
            for item in getattr(realization, "nodes", ())
            if getattr(item, "name", None) == name
        ),
        None,
    )


def published_url(realization: object, name: str, port: int, scheme: str) -> str | None:
    """Resolve one loopback-only published service URL."""

    result = None
    node = find_node(realization, name)
    if node is not None:
        matches = [
            item
            for item in getattr(node, "published_ports", ())
            if getattr(item, "container_port", None) == port
            and getattr(item, "protocol", "tcp") == "tcp"
        ]
        if len(matches) == 1 and getattr(matches[0], "host_port", None) is not None:
            host = getattr(matches[0], "host_ip", "127.0.0.1")
            if host in {"127.0.0.1", "::1", "localhost"}:
                result = f"{scheme}://127.0.0.1:{matches[0].host_port}"
    return result


def generated_output(
    realization: object, project_dir: Path, provenance: str, output_name: str
) -> str | None:
    """Read one bounded generated output rooted beneath its admitted artifact."""

    result = None
    artifacts = [
        item
        for item in getattr(realization, "generated_artifacts", ())
        if getattr(item, "provenance", None) == provenance
    ]
    if len(artifacts) == 1:
        outputs = [
            item
            for item in getattr(artifacts[0], "outputs", ())
            if getattr(item, "name", None) == output_name
        ]
        if len(outputs) == 1:
            root = artifact_source_path(project_dir, artifacts[0]).resolve()
            target = (root / outputs[0].path).resolve()
            if target.is_relative_to(root):
                try:
                    value = target.read_text(encoding="utf-8").strip()
                except OSError:
                    value = ""
                result = value or None
    return result


def content_identities(realization: object) -> dict[str, str] | None:
    """Project the two exact admitted Suricata content identities."""

    required = {"suricata-config", "suricata-local-rules"}
    identities: dict[str, str] = {}
    valid = True
    for placement in getattr(realization, "placements", ()):
        content = getattr(placement, "content", None)
        name = getattr(content, "content_name", None)
        if name not in required:
            continue
        artifact_id = getattr(content, "artifact_id", None)
        digest = getattr(content, "artifact_digest", None)
        if not isinstance(artifact_id, str) or not isinstance(digest, str):
            valid = False
            break
        identities[name] = f"{artifact_id}@{digest}"
    return identities if valid and set(identities) == required else None


def webapp_endpoint(realization: object) -> tuple[str, int] | None:
    """Resolve the unique static Kali-to-webapp HTTP endpoint."""

    kali = find_node(realization, "kali")
    webapp = find_node(realization, "webapp")
    result: tuple[str, int] | None = None
    if kali is not None and webapp is not None:
        kali_networks = dict(getattr(kali, "static_address_assignments", ()))
        web_networks = dict(getattr(webapp, "static_address_assignments", ()))
        shared = sorted(set(kali_networks) & set(web_networks))
        http = [
            item
            for item in getattr(webapp, "services", ())
            if getattr(item, "name", None) == "http"
            and getattr(item, "protocol", "tcp") == "tcp"
        ]
        if shared and len(http) == 1:
            port = getattr(http[0], "port", None)
            if isinstance(port, int) and 0 < port <= 65535:
                # Multiple authored paths may connect Kali and the application.
                # Choose one deterministically; the traffic apparatus uses the
                # same rule, so collection and observation stay on one path.
                result = (web_networks[shared[0]], port)
    return result


def webapp_address(realization: object) -> str | None:
    """Resolve the unique static Kali-to-webapp address."""

    endpoint = webapp_endpoint(realization)
    return endpoint[0] if endpoint is not None else None


def connector_projection(
    value: object, *, cortex_context: bool = False
) -> dict[str, str] | None:
    """Find and project one healthy Cortex connector from a bounded response."""

    pending = deque([(value, cortex_context)])
    result = None
    while pending and result is None:
        current, inherited_context = pending.popleft()
        if isinstance(current, Mapping):
            name = str(current.get("name", current.get("service", "")))[:128]
            status = str(current.get("status", "")).upper()
            local_context = inherited_context or "cortex" in name.lower()
            if local_context and status == "OK":
                result = {"name": name or "cortex", "status": "OK"}
                continue
            pending.extend(
                (
                    item,
                    local_context or "cortex" in str(key).lower(),
                )
                for key, item in current.items()
            )
        elif isinstance(current, Sequence) and not isinstance(current, str | bytes):
            pending.extend((item, inherited_context) for item in current)
    return result


def inside_window(value: object, start_iso: str, end_iso: str) -> bool:
    """Return whether an ISO timestamp falls inside the closed evidence window."""

    try:
        instant = datetime.fromisoformat(str(value).replace("Z", UTC_OFFSET))
        start = datetime.fromisoformat(start_iso.replace("Z", UTC_OFFSET))
        end = datetime.fromisoformat(end_iso.replace("Z", UTC_OFFSET))
    except (TypeError, ValueError):
        return False
    return start <= instant <= end


__all__ = (
    "MAX_SOURCE_BYTES",
    "bounded",
    "connector_projection",
    "content_identities",
    "find_node",
    "generated_output",
    "inside_window",
    "published_url",
    "utc_iso_now",
    "webapp_address",
    "webapp_endpoint",
)
