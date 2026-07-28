"""Production assembly for the guest-side participant workbench."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from aptl.core.runstore import LocalRunStore
from aptl.core.session import ScenarioSession
from aptl.workbench.agent import ClaudeCodeManagedAgentAdapter
from aptl.workbench.app import ParticipantAuthorizer, create_participant_workbench_app
from aptl.workbench.credentials import EphemeralCredentialBroker
from aptl.workbench.runtime import WorkbenchRuntime


@dataclass(frozen=True)
class ApplianceWorkbenchSettings:
    """Trusted paths supplied by the signed appliance launch definition."""

    payload_root: Path
    state_dir: Path
    claude_executable: Path
    model: str
    node_executable: Path = Path("/usr/bin/node")


def create_appliance_workbench_app(
    settings: ApplianceWorkbenchSettings,
    *,
    secret_source: Mapping[str, str],
    authorizer: ParticipantAuthorizer,
) -> FastAPI:
    """Wire the concrete agent, credential, session, run-store, and HTTP layers."""
    state_dir = settings.state_dir.resolve()
    broker = EphemeralCredentialBroker(secret_source)
    adapter = ClaudeCodeManagedAgentAdapter(
        claude_executable=settings.claude_executable,
        work_dir=state_dir / "workbench" / "agent-work",
    )
    runtime = WorkbenchRuntime(
        ScenarioSession(state_dir),
        adapter,
        LocalRunStore(state_dir / "runs"),
        payload_root=settings.payload_root,
        generated_config_dir=state_dir / "workbench" / "mcp-config",
        credential_broker=broker,
        model=settings.model,
        node_executable=settings.node_executable,
    )
    return create_participant_workbench_app(runtime, authorizer)
