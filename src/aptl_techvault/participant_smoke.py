"""TechVault's participant-profile MCP smoke answer key."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from aptl.validation.participant_mcp_smoke import McpSmokeOperation

_RECENT_SSH_ALERT_QUERY = {
    "size": 1,
    "query": {
        "bool": {
            "must": [{"match": {"rule.id": "5710"}}],
            "filter": [{"range": {"@timestamp": {"gte": "now-15m"}}}],
        }
    },
}


def _text_content(result: Mapping[str, object]) -> list[str]:
    """Return the text blocks of one MCP tool result, ignoring other shapes."""

    content = result.get("content")
    if not isinstance(content, Sequence) or isinstance(content, str | bytes):
        return []
    return [
        str(item["text"])
        for item in content
        if isinstance(item, Mapping)
        and item.get("type") == "text"
        and isinstance(item.get("text"), str)
    ]


def _decoded_text_payloads(result: Mapping[str, object]) -> list[object]:
    """Return each text block that parses as JSON, skipping those that do not."""

    payloads: list[object] = []
    for text in _text_content(result):
        try:
            payloads.append(json.loads(text))
        except json.JSONDecodeError:
            continue
    return payloads


def _is_alert_envelope(value: Mapping[str, object]) -> bool:
    """Whether this one mapping is a search envelope carrying a non-empty hit list."""

    hits = value.get("hits")
    inner = hits.get("hits") if isinstance(hits, Mapping) else None
    return isinstance(inner, list) and bool(inner)


def _has_alert_hit(value: object) -> bool:
    """Whether any nested search envelope in ``value`` carries a hit.

    The indexer nests its result an unpredictable number of levels down inside
    the MCP payload, so the search is recursive rather than path-based.
    """

    if isinstance(value, list):
        return any(_has_alert_hit(item) for item in value)
    if not isinstance(value, Mapping):
        return False
    return _is_alert_envelope(value) or any(
        _has_alert_hit(item) for item in value.values()
    )


def _kali_user(result: Mapping[str, object]) -> bool:
    """Whether the shell answered as the scenario's unprivileged attacker user."""

    return result.get("isError") is not True and any(
        "uid=1000(kali)" in text for text in _text_content(result)
    )


def _attack_completed(result: Mapping[str, object]) -> bool:
    """Whether the attack command ran to completion and said so on stdout."""

    for payload in _decoded_text_payloads(result):
        if not isinstance(payload, Mapping) or payload.get("success") is not True:
            continue
        output = payload.get("output")
        stdout = output.get("stdout") if isinstance(output, Mapping) else None
        if isinstance(stdout, str) and stdout.rstrip().endswith("done"):
            return True
    return False


def _alert_hit(result: Mapping[str, object]) -> bool:
    """Whether the SIEM answered the correlation query with at least one alert."""

    return result.get("isError") is not True and any(
        _has_alert_hit(payload) for payload in _decoded_text_payloads(result)
    )


PARTICIPANT_SMOKE_OPERATIONS = (
    McpSmokeOperation(
        check_id="mcp.red.kali-command",
        server_id="aptl-red",
        tool_name="kali_run_command",
        arguments={"command": "id"},
        validates=_kali_user,
    ),
    McpSmokeOperation(
        check_id="mcp.red.ssh-authentication-attack",
        server_id="aptl-red",
        tool_name="kali_run_command",
        arguments={
            "command": (
                "for u in aptl-a aptl-b aptl-c aptl-d aptl-e aptl-f; do "
                "ssh -o BatchMode=yes -o StrictHostKeyChecking=no "
                '-o ConnectTimeout=5 "$u"@172.20.2.20 true 2>/dev/null '
                "|| true; done; echo done"
            )
        },
        validates=_attack_completed,
    ),
    McpSmokeOperation(
        check_id="mcp.blue.indexer-investigation",
        server_id="aptl-indexer",
        tool_name="indexer_query",
        arguments={"body": _RECENT_SSH_ALERT_QUERY},
        validates=_alert_hit,
    ),
    McpSmokeOperation(
        check_id="mcp.blue.wazuh-investigation",
        server_id="aptl-wazuh",
        tool_name="wazuh_query_alerts",
        arguments={"body": _RECENT_SSH_ALERT_QUERY},
        validates=_alert_hit,
    ),
)

__all__ = ["PARTICIPANT_SMOKE_OPERATIONS"]
