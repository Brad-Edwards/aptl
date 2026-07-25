"""Closed, secret-free participant workbench profile definitions."""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from aptl.utils.pathsafe import PathContainmentError, create_exclusive_nofollow

_TRACE_ID_RE = re.compile(r"^[a-f0-9]{32}$")
class WorkbenchConfigurationError(ValueError):
    """The requested profile cannot safely produce a client configuration."""


class ProfileId(str, Enum):
    """The only participant capability compartments admitted by this release."""

    RED = "red"
    BLUE = "blue"


@dataclass(frozen=True)
class ServerProfile:
    """A built MCP artifact and the aliases it requires from its supervisor."""

    server_id: str
    artifact_ref: str
    credential_aliases: tuple[str, ...] = ()
    tool_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkbenchProfile:
    """An immutable launch compartment, not a client-side tool filter."""

    profile_id: ProfileId
    servers: tuple[ServerProfile, ...]
    bookmark_refs: tuple[str, ...]
    policy_version: str = "participant-workbench-profile/v1"

    @property
    def server_ids(self) -> tuple[str, ...]:
        return tuple(server.server_id for server in self.servers)

    @property
    def credential_aliases(self) -> tuple[str, ...]:
        return tuple(
            sorted({alias for server in self.servers for alias in server.credential_aliases})
        )


_RED = WorkbenchProfile(
    profile_id=ProfileId.RED,
    servers=(
        ServerProfile(
            "aptl-red",
            "mcp/mcp-red/build/index.js",
            tool_names=(
                "kali_info",
                "kali_run_command",
                "kali_interactive_session",
                "kali_background_session",
                "kali_session_command",
                "kali_list_sessions",
                "kali_close_session",
                "kali_get_session_output",
                "kali_close_all_sessions",
            ),
        ),
    ),
    bookmark_refs=("aptl-guide", "kali-desktop"),
)

_BLUE = WorkbenchProfile(
    profile_id=ProfileId.BLUE,
    servers=(
        ServerProfile(
            "aptl-casemgmt",
            "mcp/mcp-casemgmt/build/index.js",
            ("THEHIVE_API_KEY",),
            (
                "cases_list_cases",
                "cases_create_case",
                "cases_add_observable",
                "cases_update_case",
                "cases_create_alert",
            ),
        ),
        ServerProfile(
            "aptl-indexer",
            "mcp/mcp-indexer/build/index.js",
            ("INDEXER_PASSWORD",),
            (
                "indexer_query",
                "indexer_create_rule",
                "indexer_restart_manager",
                "indexer_get_rule_file",
            ),
        ),
        ServerProfile(
            "aptl-network",
            "mcp/mcp-network/build/index.js",
            ("INDEXER_PASSWORD",),
            (
                "network_query_ids_alerts",
                "network_query_dns_events",
                "network_query_network_flows",
                "network_query_web_attacks",
            ),
        ),
        ServerProfile(
            "aptl-soar",
            "mcp/mcp-soar/build/index.js",
            ("SHUFFLE_API_KEY",),
            (
                "soar_list_workflows",
                "soar_get_workflow",
                "soar_execute_workflow",
                "soar_list_executions",
                "soar_search_workflows",
            ),
        ),
        ServerProfile(
            "aptl-threatintel",
            "mcp/mcp-threatintel/build/index.js",
            ("MISP_API_KEY",),
            (
                "threatintel_search_iocs",
                "threatintel_get_events",
                "threatintel_add_indicator",
                "threatintel_correlate_observable",
            ),
        ),
        ServerProfile(
            "aptl-wazuh",
            "mcp/mcp-wazuh/build/index.js",
            ("WAZUH_PASSWORD",),
            (
                "wazuh_query_alerts",
                "wazuh_query_logs",
                "wazuh_create_detection_rule",
            ),
        ),
    ),
    bookmark_refs=("aptl-guide", "soc-wazuh", "soc-thehive", "soc-misp", "soc-shuffle"),
)

_PROFILES = {profile.profile_id: profile for profile in (_RED, _BLUE)}


def profile_for(profile: ProfileId | str) -> WorkbenchProfile:
    """Return an admitted profile or reject an unrecognised capability set."""
    try:
        return _PROFILES[ProfileId(profile)]
    except ValueError as exc:
        raise WorkbenchConfigurationError("unknown participant profile") from exc


def _validate_run_id(run_id: str) -> str:
    if not _TRACE_ID_RE.fullmatch(run_id):
        raise WorkbenchConfigurationError("run_id must be the active 32-character trace id")
    return run_id


def _validate_aliases(
    profile: WorkbenchProfile, credential_aliases: Collection[str]
) -> None:
    available = set(credential_aliases)
    missing = [alias for alias in profile.credential_aliases if alias not in available]
    if missing:
        raise WorkbenchConfigurationError(
            "missing required credential alias: " + ", ".join(missing)
        )


def _validate_artifacts(profile: WorkbenchProfile, payload_root: Path) -> None:
    root = payload_root.resolve()
    for server in profile.servers:
        artifact = (root / server.artifact_ref).resolve()
        if not artifact.is_relative_to(root) or not artifact.is_file():
            raise WorkbenchConfigurationError(
                f"missing released MCP artifact for {server.server_id}"
            )


def verify_profile_tool_inventory(
    profile: ProfileId | str, inventory: Mapping[str, Collection[str]]
) -> None:
    """Reject a launched profile unless every server reports its exact tools/list set."""
    selected = profile_for(profile)
    expected = {server.server_id: frozenset(server.tool_names) for server in selected.servers}
    actual = {server_id: frozenset(tool_names) for server_id, tool_names in inventory.items()}
    if actual != expected:
        raise WorkbenchConfigurationError("MCP tool inventory does not match the selected profile")


def render_profile_config(
    *,
    profile: ProfileId | str,
    payload_root: Path,
    output_dir: Path,
    run_id: str,
    credential_aliases: Collection[str],
) -> Path:
    """Render one private, credential-free client config for an active run.

    Only credential aliases are admitted here; values stay with the
    management-owned credential broker while it starts the MCP processes.
    """
    selected = profile_for(profile)
    active_run_id = _validate_run_id(run_id)
    _validate_aliases(selected, credential_aliases)
    _validate_artifacts(selected, payload_root)

    document = {
        "schemaVersion": "aptl-participant-mcp-client/v1",
        "profile": selected.profile_id.value,
        "runId": active_run_id,
        "policyVersion": selected.policy_version,
        "mcpServers": {
            server.server_id: {
                "transport": "management-owned",
                "artifactRef": server.artifact_ref,
                "credentialAliases": list(server.credential_aliases),
            }
            for server in selected.servers
        },
    }
    output_parent = output_dir.parent
    relative_path = f"{output_dir.name}/{selected.profile_id.value}-{active_run_id}.json"
    try:
        create_exclusive_nofollow(
            output_parent,
            relative_path,
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
    except (FileExistsError, PathContainmentError) as exc:
        raise WorkbenchConfigurationError("unable to create private profile config") from exc
    return output_parent / relative_path
