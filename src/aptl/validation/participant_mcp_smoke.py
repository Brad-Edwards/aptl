"""Generic executor for a plugin-owned participant MCP smoke plan."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
import re

from aptl.validation.mcp_protocol import McpProtocolError, call_mcp_tool
from aptl.validation.participant_profile import ResolvedParticipantProfile
from aptl.validation.participant_qualification import QualificationCheckEvidence


class ParticipantMcpSmokeError(ValueError):
    """The admitted profile cannot run its exact MCP smoke surface."""


PARTICIPANT_SMOKE_ENTRY_POINT_GROUP = "aptl.participant_mcp_smoke_plans"
_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_MAX_OPERATIONS = 64


@dataclass(frozen=True)
class McpRegistration:
    """One management-owned released MCP process registration."""

    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]


@dataclass(frozen=True)
class McpSmokeOperation:
    """One plugin-owned readiness check bound to a released MCP tool call."""

    check_id: str
    server_id: str
    tool_name: str
    arguments: Mapping[str, object]
    validates: Callable[[Mapping[str, object]], bool]


def _validate_profile_binding(
    profile: ResolvedParticipantProfile,
    operations: Sequence[McpSmokeOperation],
) -> None:
    """Require the smoke registry to equal the admitted MCP readiness surface."""

    allowed = set(profile.mcp_server_ids)
    operation_servers = {operation.server_id for operation in operations}
    if operation_servers != allowed:
        raise ParticipantMcpSmokeError(
            "profile MCP operation registry does not match the allowed surface"
        )
    readiness = {
        (check.check_id, check.subject_id)
        for check in profile.readiness.checks
        if check.kind == "mcp-tool"
    }
    expected = {(operation.check_id, operation.server_id) for operation in operations}
    if readiness != expected:
        raise ParticipantMcpSmokeError(
            "profile MCP readiness suite does not match the operation registry"
        )


def _profile_selector(profile: ResolvedParticipantProfile) -> str:
    """Return the bounded installed-plan selector for one admitted profile."""

    selector = f"{profile.manifest.profile_id}.{profile.manifest.scenario.catalog_id}"
    if _SAFE_ID.fullmatch(selector) is None:
        raise ParticipantMcpSmokeError("participant smoke selector is invalid")
    return selector


def _installed_plan_entry_points() -> list[metadata.EntryPoint]:
    """Return installed participant-smoke plan entry points."""

    return list(metadata.entry_points(group=PARTICIPANT_SMOKE_ENTRY_POINT_GROUP))


def _load_installed_plan(selector: str) -> object:
    exact = [
        entry_point
        for entry_point in _installed_plan_entry_points()
        if entry_point.name == selector
    ]
    if len(exact) != 1:
        raise ParticipantMcpSmokeError(
            "exactly one compatible participant smoke plan must be installed"
        )
    try:
        return exact[0].load()
    except Exception:
        raise ParticipantMcpSmokeError(
            "participant smoke plan could not be loaded"
        ) from None


def _valid_operation(operation: McpSmokeOperation) -> bool:
    identifiers = (operation.check_id, operation.server_id, operation.tool_name)
    return (
        all(_SAFE_ID.fullmatch(value) is not None for value in identifiers)
        and isinstance(operation.arguments, Mapping)
        and callable(operation.validates)
    )


def _validated_operations(loaded: object) -> tuple[McpSmokeOperation, ...]:
    valid_container = (
        isinstance(loaded, tuple)
        and bool(loaded)
        and len(loaded) <= _MAX_OPERATIONS
    )
    if not valid_container or not all(
        isinstance(item, McpSmokeOperation) for item in loaded
    ):
        raise ParticipantMcpSmokeError("participant smoke plan is malformed")
    operations = tuple(loaded)
    if not all(_valid_operation(operation) for operation in operations):
        raise ParticipantMcpSmokeError("participant smoke plan is malformed")
    return operations


def resolve_participant_mcp_smoke_operations(
    profile: ResolvedParticipantProfile,
) -> tuple[McpSmokeOperation, ...]:
    """Load the one installed operation plan matching an admitted profile."""

    selector = _profile_selector(profile)
    operations = _validated_operations(_load_installed_plan(selector))
    _validate_profile_binding(profile, operations)
    return operations


def run_participant_mcp_smoke(
    profile: ResolvedParticipantProfile,
    registrations: Mapping[str, McpRegistration],
    operations: Sequence[McpSmokeOperation] | None = None,
) -> tuple[QualificationCheckEvidence, ...]:
    """Resolve and invoke every admitted MCP operation exactly once."""

    operations = (
        resolve_participant_mcp_smoke_operations(profile)
        if operations is None
        else tuple(operations)
    )
    _validate_profile_binding(profile, operations)
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
    for operation in operations:
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
            passed = operation.validates(result)
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


__all__ = [
    "PARTICIPANT_SMOKE_ENTRY_POINT_GROUP",
    "McpRegistration",
    "McpSmokeOperation",
    "ParticipantMcpSmokeError",
    "resolve_participant_mcp_smoke_operations",
    "run_participant_mcp_smoke",
]
