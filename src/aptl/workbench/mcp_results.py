"""Redact tool data while retaining connection-scoped terminal handles."""

from __future__ import annotations

import json
import re
from typing import Any

from aptl.utils.redaction import redact

_SESSION_TOOLS = frozenset(
    "kali_" + suffix
    for suffix in (
        "interactive_session",
        "background_session",
        "session_command",
        "list_sessions",
        "close_session",
        "get_session_output",
        "close_all_sessions",
    )
)


def _session_row(value: dict[str, Any]) -> dict[str, Any]:
    """Redact credentials while preserving validated terminal handle fields."""
    safe = redact(value)
    identifier = value.get("session_id")
    if (
        isinstance(identifier, str)
        and re.fullmatch(r"\w[A-Za-z0-9._-]{0,127}", identifier, re.ASCII)
        and ".." not in identifier
    ):
        safe["session_id"] = identifier
    if value.get("session_mode") in ("normal", "raw"):
        safe["session_mode"] = value["session_mode"]
    return safe


def _session_payload(value: dict[str, Any], tool: str) -> dict[str, Any]:
    """Retain typed terminal session inventory after redaction."""
    safe = _session_row(value)
    if tool == "kali_list_sessions" and isinstance(value.get("sessions"), list):
        safe["sessions"] = [
            _session_row(row) for row in value["sessions"] if isinstance(row, dict)
        ]
    count = value.get("total_sessions")
    if type(count) is int and count >= 0:
        safe["total_sessions"] = count
    return safe


def redact_mcp_result(result: dict[str, Any], server: str, tool: str) -> dict[str, Any]:
    """Keep only the red MCP's typed terminal handles, never API login sessions.

    Handles address sessions inside this caller's isolated MCP process. They
    are needed for subsequent commands and closure; they grant no transport or
    service authentication. All command output and credential fields still use
    the shared redactor. No global redaction allowlist is relaxed.
    """
    safe = redact(result)
    if server != "aptl-red" or tool not in _SESSION_TOOLS:
        return safe
    content = result.get("content", [])
    if not isinstance(content, list):
        return safe
    for index, block in enumerate(content):
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        try:
            payload = json.loads(block.get("text", ""))
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            safe["content"][index]["text"] = json.dumps(_session_payload(payload, tool))
    return safe
