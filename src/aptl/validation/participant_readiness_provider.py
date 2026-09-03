"""Admitted decision-only provider launch for participant readiness."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from aptl.backends.raes_participant_driver import MAX_PARTICIPANT_DECISION_SECONDS
from aptl.backends.raes_participant_provider import (
    ManagedAgentSelectionProvider,
    ParticipantSelectionProvider,
)
from aptl.workbench.agent import ClaudeCodeManagedAgentAdapter, _admitted_executable
from aptl.workbench.codex_agent import CodexManagedAgentAdapter
from aptl.workbench.credentials import (
    EphemeralCredentialBroker,
    WorkbenchCredentialError,
)
from aptl.workbench.participant_source_binding import (
    CredentialBindingEvidence,
    ProcessEnvironmentCredentialResolver,
    configured_source_evidence,
    observe_local_cleanup,
    participant_binding_error,
)
from aptl.workbench.runtime import DecisionAgentLaunch

if TYPE_CHECKING:
    from aptl.core.config import AptlConfig, ProcessEnvironmentCredentialSource

_PROVIDER_VERSION_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "NO_COLOR": "1",
}
_INSTALLED_VERSION_UNAVAILABLE = "installed participant provider version is unavailable"
MAX_INSTALLED_PARTICIPANT_PROMPT_CHARS = 32_768
_REQUIRED_ISOLATION_CONTROLS = {
    "claude": (
        "minimal-child-environment",
        "private-home",
        "private-claude-config",
        "claude-bare-api-key-mode",
    ),
    "codex": (
        "minimal-child-environment",
        "private-home",
        "private-codex-home",
        "codex-user-config-disabled",
        "codex-ephemeral-mode",
    ),
}


def build_selection_provider(
    provider_name: str,
    *,
    config: AptlConfig,
    project_dir: Path,
    run_id: str,
) -> tuple[
    ParticipantSelectionProvider,
    Callable[[], None],
    CredentialBindingEvidence | None,
]:
    """Build one deterministic or admitted installed selection provider."""

    if provider_name == "deterministic":
        from aptl.backends.raes_participant_provider import (
            DeterministicSelectionProvider,
        )

        return DeterministicSelectionProvider(), _noop, None
    model = config.experiment.participant_models.model_for(provider_name)
    source, evidence = _configured_source(provider_name, config, run_id)
    executable, version = _admitted_provider(provider_name, evidence)
    work_dir = project_dir / ".aptl" / "participant-agents" / run_id / provider_name
    broker, binding = _configured_binding(provider_name, run_id, source, evidence)
    launch = DecisionAgentLaunch(
        provider=provider_name,
        run_id=run_id,
        model=model,
    )
    provider = _launch_installed_provider(
        launch,
        executable,
        work_dir,
        version,
        binding,
        broker,
        evidence,
    )
    return provider, _cleanup_callback(provider, broker, run_id, evidence), evidence


def _configured_source(
    provider_name: str,
    config: AptlConfig,
    run_id: str,
) -> tuple[ProcessEnvironmentCredentialSource, CredentialBindingEvidence]:
    """Return the selected source with evidence for pre-acquisition failure."""

    try:
        source = config.experiment.participant_credential_sources.source_for(
            provider_name
        )
    except ValueError as exc:
        evidence = CredentialBindingEvidence(
            provider=provider_name,
            run_id=run_id,
            source_kind=None,
            descriptor_sha256=None,
            config_ref=(f"experiment.participant_credential_sources.{provider_name}"),
            delivery_contract=f"aptl.{provider_name}-credential-environment/v1",
            acquisition="source-not-configured",
        )
        raise participant_binding_error(
            "installed participant credential source is not configured", evidence
        ) from exc
    return source, configured_source_evidence(provider_name, source, run_id)


def _admitted_provider(
    provider_name: str,
    evidence: CredentialBindingEvidence,
) -> tuple[Path, str]:
    """Admit the installed executable and resolve its stable version."""

    discovered_executable = shutil.which(provider_name)
    if discovered_executable is None:
        evidence.acquisition = "not-requested"
        raise participant_binding_error(
            "installed participant provider is unavailable", evidence
        )
    try:
        executable = _admitted_executable(Path(discovered_executable))
        version = installed_version(executable)
    except (OSError, RuntimeError, ValueError) as exc:
        evidence.acquisition = "not-requested"
        raise participant_binding_error(str(exc), evidence) from exc
    return executable, version


def _configured_binding(
    provider_name: str,
    run_id: str,
    source: ProcessEnvironmentCredentialSource,
    evidence: CredentialBindingEvidence,
) -> tuple[EphemeralCredentialBroker, Mapping[str, str]]:
    """Resolve one source and place it in the incumbent binding owner."""

    credential_name = (
        "ANTHROPIC_API_KEY" if provider_name == "claude" else "CODEX_API_KEY"
    )
    resolver = ProcessEnvironmentCredentialResolver(os.environ)
    acquired, evidence = resolver.acquire(
        provider_name,
        run_id,
        source=source,
        delivery_alias=credential_name,
        evidence=evidence,
    )
    broker = EphemeralCredentialBroker(acquired)
    try:
        binding = broker.prepare_named(provider_name, run_id, (credential_name,))
    except WorkbenchCredentialError as exc:
        evidence.acquisition = "binding-conflict"
        observe_local_cleanup(evidence, succeeded=True)
        raise participant_binding_error(
            "configured participant credential binding failed", evidence
        ) from exc
    return broker, binding


def _launch_installed_provider(
    launch: DecisionAgentLaunch,
    executable: Path,
    work_dir: Path,
    version: str,
    binding: Mapping[str, str],
    broker: EphemeralCredentialBroker,
    evidence: CredentialBindingEvidence,
) -> ManagedAgentSelectionProvider:
    """Launch one adapter only after source acquisition and verify isolation."""

    adapter: ClaudeCodeManagedAgentAdapter | CodexManagedAgentAdapter | None = None
    handle: object | None = None
    try:
        adapter = _launch_adapter(launch.provider, executable, work_dir)
        handle = adapter.launch(launch, binding)
        controls = adapter.credential_isolation_controls(handle)
        if controls != _REQUIRED_ISOLATION_CONTROLS[launch.provider]:
            raise ValueError("installed participant credential isolation is incomplete")
        evidence.isolation_controls_applied = controls
        evidence.isolation = "controls-enforced"
        inventory = adapter.list_tools(handle)
    except (OSError, RuntimeError, ValueError) as exc:
        evidence.isolation = "failed"
        _discard_failed_launch(
            adapter,
            handle,
            broker,
            launch.provider,
            launch.run_id,
            evidence,
        )
        raise participant_binding_error(
            "installed participant provider launch failed", evidence
        ) from exc
    if inventory:
        evidence.isolation = "failed"
        _discard_failed_launch(
            adapter,
            handle,
            broker,
            launch.provider,
            launch.run_id,
            evidence,
        )
        raise participant_binding_error(
            "decision-only provider exposed action tools", evidence
        ) from None
    return ManagedAgentSelectionProvider(
        adapter=adapter,
        handle=handle,
        provider_name=launch.provider,
        model=launch.model,
        implementation_name=f"aptl-installed-{launch.provider}",
        implementation_version=version,
    )


def _cleanup_callback(
    provider: ManagedAgentSelectionProvider,
    broker: EphemeralCredentialBroker,
    run_id: str,
    evidence: CredentialBindingEvidence,
) -> Callable[[], None]:
    """Build cleanup that always drops the local binding and records outcome."""

    def cleanup() -> None:
        """Close the provider and remove APTL's local credential binding."""

        cleanup_error: Exception | None = None
        try:
            provider.close()
        except (OSError, RuntimeError, ValueError) as exc:
            cleanup_error = exc
        finally:
            broker.destroy_named(provider.provider_name, run_id)
            observe_local_cleanup(evidence, succeeded=cleanup_error is None)
        if cleanup_error is not None:
            raise participant_binding_error(
                "installed participant provider cleanup failed", evidence
            ) from cleanup_error

    return cleanup


def _discard_failed_launch(
    adapter: ClaudeCodeManagedAgentAdapter | CodexManagedAgentAdapter | None,
    handle: object | None,
    broker: EphemeralCredentialBroker,
    provider_name: str,
    run_id: str,
    evidence: CredentialBindingEvidence,
) -> Exception | None:
    """Close a partial launch and preserve a secret-free cleanup outcome."""

    cleanup_error: Exception | None = None
    if adapter is not None and handle is not None:
        try:
            adapter.close(handle)
        except (OSError, RuntimeError, ValueError) as exc:
            cleanup_error = exc
    broker.destroy_named(provider_name, run_id)
    observe_local_cleanup(evidence, succeeded=cleanup_error is None)
    return cleanup_error


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
            max_prompt_chars=MAX_INSTALLED_PARTICIPANT_PROMPT_CHARS,
        )
    return CodexManagedAgentAdapter(
        codex_executable=executable,
        work_dir=work_dir,
        timeout_seconds=MAX_PARTICIPANT_DECISION_SECONDS,
        max_prompt_chars=MAX_INSTALLED_PARTICIPANT_PROMPT_CHARS,
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
