"""Real semantic MCP smoke operations for the bounded participant profile."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from aptl.validation.mcp_protocol import McpProtocolError, call_mcp_tool
from aptl.validation.participant_profile import ResolvedParticipantProfile
from aptl.validation.participant_qualification import QualificationCheckEvidence


class ParticipantMcpSmokeError(ValueError):
    """The admitted profile cannot run its exact MCP smoke surface."""


@dataclass(frozen=True)
class McpRegistration:
    """One management-owned released MCP process registration."""

    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]


@dataclass(frozen=True)
class _SmokeOperation:
    """One readiness check bound to one released MCP tool call."""

    check_id: str
    server_id: str
    tool_name: str
    arguments: Mapping[str, object]
    semantic_kind: str


_RECENT_SSH_ALERT_QUERY = {
    "size": 1,
    "query": {
        "bool": {
            "must": [{"match": {"rule.id": "5710"}}],
            "filter": [{"range": {"@timestamp": {"gte": "now-15m"}}}],
        }
    },
}

_OPERATIONS = (
    _SmokeOperation(
        check_id="mcp.red.kali-command",
        server_id="aptl-red",
        tool_name="kali_run_command",
        arguments={"command": "id"},
        semantic_kind="kali-user",
    ),
    _SmokeOperation(
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
        semantic_kind="attack-complete",
    ),
    _SmokeOperation(
        check_id="mcp.blue.indexer-investigation",
        server_id="aptl-indexer",
        tool_name="indexer_query",
        arguments={"body": _RECENT_SSH_ALERT_QUERY},
        semantic_kind="alert-hit",
    ),
    _SmokeOperation(
        check_id="mcp.blue.wazuh-investigation",
        server_id="aptl-wazuh",
        tool_name="wazuh_query_alerts",
        arguments={"body": _RECENT_SSH_ALERT_QUERY},
        semantic_kind="alert-hit",
    ),
)


def _text_content(result: Mapping[str, object]) -> list[str]:
    """Return only text blocks from an MCP tool result."""

    content = result.get("content")
    if not isinstance(content, Sequence) or isinstance(content, str | bytes):
        return []
    texts: list[str] = []
    for item in content:
        if not isinstance(item, Mapping) or item.get("type") != "text":
            continue
        value = item.get("text")
        if isinstance(value, str):
            texts.append(value)
    return texts


def _has_alert_hit(value: object) -> bool:
    """Return whether a nested indexer response contains at least one hit."""

    found = False
    if isinstance(value, Mapping):
        hits = value.get("hits")
        if isinstance(hits, Mapping):
            rows = hits.get("hits")
            if isinstance(rows, list) and rows:
                found = True
        if not found:
            found = any(_has_alert_hit(item) for item in value.values())
    elif isinstance(value, list):
        found = any(_has_alert_hit(item) for item in value)
    return found


def _decoded_text_payloads(texts: Sequence[str]) -> list[object]:
    """Decode the JSON text blocks emitted by the released MCP servers."""

    payloads: list[object] = []
    for text in texts:
        try:
            payloads.append(json.loads(text))
        except json.JSONDecodeError:
            continue
    return payloads


def _attack_completed(payload: object) -> bool:
    """Validate the bounded failed-authentication attack completion marker."""

    if not isinstance(payload, Mapping) or payload.get("success") is not True:
        return False
    output = payload.get("output")
    stdout = output.get("stdout") if isinstance(output, Mapping) else None
    return isinstance(stdout, str) and stdout.rstrip().endswith("done")


def _semantic_passed(kind: str, result: Mapping[str, object]) -> bool:
    """Validate semantic evidence without accepting result text as a verdict."""

    passed = False
    if result.get("isError") is not True:
        texts = _text_content(result)
        if kind == "kali-user":
            passed = any("uid=1000(kali)" in text for text in texts)
        else:
            payloads = _decoded_text_payloads(texts)
            if kind == "attack-complete":
                passed = any(_attack_completed(payload) for payload in payloads)
            elif kind == "alert-hit":
                passed = any(_has_alert_hit(payload) for payload in payloads)
    return passed


def _validate_profile_binding(profile: ResolvedParticipantProfile) -> None:
    """Require the smoke registry to equal the admitted MCP readiness surface."""

    allowed = set(profile.mcp_server_ids)
    operation_servers = {operation.server_id for operation in _OPERATIONS}
    if operation_servers != allowed:
        raise ParticipantMcpSmokeError(
            "profile MCP operation registry does not match the allowed surface"
        )
    readiness = {
        (check.check_id, check.subject_id)
        for check in profile.readiness.checks
        if check.kind == "mcp-tool"
    }
    expected = {(operation.check_id, operation.server_id) for operation in _OPERATIONS}
    if readiness != expected:
        raise ParticipantMcpSmokeError(
            "profile MCP readiness suite does not match the operation registry"
        )


def run_participant_mcp_smoke(
    profile: ResolvedParticipantProfile,
    registrations: Mapping[str, McpRegistration],
) -> tuple[QualificationCheckEvidence, ...]:
    """Invoke every allowed MCP's bounded real backend operation exactly once."""

    _validate_profile_binding(profile)
    allowed = set(profile.mcp_server_ids)
    if set(registrations) != allowed:
        raise ParticipantMcpSmokeError(
            "MCP registration surface does not match the participant profile"
        )
    timeouts = {
        check.check_id: check.timeout_seconds
        for check in profile.readiness.checks
        if check.kind == "mcp-tool"
    }
    evidence: list[QualificationCheckEvidence] = []
    expected_tools = {
        server.server_id: server.tool_names
        for workbench in profile.workbench_profiles
        for server in workbench.servers
    }
    for operation in _OPERATIONS:
        registration = registrations[operation.server_id]
        try:
            result = call_mcp_tool(
                registration.argv,
                operation.tool_name,
                operation.arguments,
                cwd=registration.cwd,
                env=registration.env,
                timeout_seconds=timeouts[operation.check_id],
                expected_tool_names=expected_tools[operation.server_id],
            )
            passed = _semantic_passed(operation.semantic_kind, result)
        except McpProtocolError:
            passed = False
        evidence.append(
            QualificationCheckEvidence(
                check_id=operation.check_id,
                status="passed" if passed else "failed",
                summary=(
                    "semantic backend operation passed"
                    if passed
                    else "semantic backend operation failed"
                ),
            )
        )
    return tuple(evidence)
