"""Admitted decision-only provider launch for participant readiness."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from aptl.backends.raes_participant_driver import MAX_PARTICIPANT_DECISION_SECONDS
from aptl.backends.raes_participant_provider import (
    ManagedAgentSelectionProvider,
    ParticipantSelectionProvider,
)
from aptl.workbench.agent import ClaudeCodeManagedAgentAdapter, _admitted_executable
from aptl.workbench.codex_agent import CodexManagedAgentAdapter
from aptl.workbench.credentials import EphemeralCredentialBroker
from aptl.workbench.runtime import DecisionAgentLaunch

_PROVIDER_VERSION_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "NO_COLOR": "1",
}
_INSTALLED_VERSION_UNAVAILABLE = "installed participant provider version is unavailable"


def build_selection_provider(
    provider_name: str,
    *,
    project_dir: Path,
    run_id: str,
) -> tuple[ParticipantSelectionProvider, Callable[[], None]]:
    """Build one deterministic or admitted installed selection provider."""

    if provider_name == "deterministic":
        from aptl.backends.raes_participant_provider import (
            DeterministicSelectionProvider,
        )

        return DeterministicSelectionProvider(), _noop
    discovered_executable = shutil.which(provider_name)
    if discovered_executable is None:
        raise ValueError(
            f"installed participant provider is unavailable: {provider_name}"
        )
    executable = _admitted_executable(Path(discovered_executable))
    version = installed_version(executable)
    work_dir = project_dir / ".aptl" / "participant-agents" / run_id / provider_name
    credential_name = (
        "ANTHROPIC_API_KEY" if provider_name == "claude" else "CODEX_API_KEY"
    )
    broker = EphemeralCredentialBroker(
        {credential_name: os.environ.get(credential_name, "")}
    )
    lease = broker.prepare_named(provider_name, run_id, (credential_name,))
    try:
        adapter = _launch_adapter(provider_name, executable, work_dir)
        handle = adapter.launch(
            DecisionAgentLaunch(provider=provider_name, run_id=run_id),
            lease,
        )
        inventory = adapter.list_tools(handle)
    except (OSError, RuntimeError, ValueError):
        broker.destroy_named(provider_name, run_id)
        raise
    if inventory:
        try:
            adapter.close(handle)
        finally:
            broker.destroy_named(provider_name, run_id)
        raise ValueError("decision-only provider exposed action tools")
    provider = ManagedAgentSelectionProvider(
        adapter=adapter,
        handle=handle,
        implementation_name=f"aptl-installed-{provider_name}",
        implementation_version=version,
    )

    def cleanup() -> None:
        """Close the provider and destroy its credential lease."""

        try:
            provider.close()
        finally:
            broker.destroy_named(provider_name, run_id)

    return provider, cleanup


def _launch_adapter(
    provider_name: str,
    executable: Path,
    work_dir: Path,
) -> ClaudeCodeManagedAgentAdapter | CodexManagedAgentAdapter:
    """Build the installed adapter with the bounded decision timeout."""

    if provider_name == "claude":
        return ClaudeCodeManagedAgentAdapter(
            claude_executable=executable,
            work_dir=work_dir,
            timeout_seconds=MAX_PARTICIPANT_DECISION_SECONDS,
        )
    return CodexManagedAgentAdapter(
        codex_executable=executable,
        work_dir=work_dir,
        timeout_seconds=MAX_PARTICIPANT_DECISION_SECONDS,
    )


def installed_version(executable: Path) -> str:
    """Resolve a bounded semantic version from an admitted executable."""

    try:
        result = subprocess.run(
            [str(executable), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=_PROVIDER_VERSION_ENVIRONMENT,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(_INSTALLED_VERSION_UNAVAILABLE) from exc
    first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    version = next(
        (
            token.strip("(),")
            for token in first_line.split()
            if _is_version_token(token.strip("(),"))
        ),
        None,
    )
    if result.returncode != 0 or version is None:
        raise ValueError(_INSTALLED_VERSION_UNAVAILABLE)
    return version


def _is_version_token(token: str) -> bool:
    """Recognize a bounded dotted numeric version with optional suffix."""

    core = token.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    return 2 <= len(parts) <= 4 and all(part.isdigit() for part in parts)


def _noop() -> None:
    """No-op cleanup for deterministic selection providers."""
