"""Ordered profile lifecycle for the participant workbench."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Collection, Mapping
from typing import Protocol

from aptl.core.runstore import RunStorageBackend
from aptl.core.session import ScenarioSession
from aptl.workbench.profiles import (
    ProfileId,
    profile_for,
    render_profile_config,
    verify_profile_tool_inventory,
)


class WorkbenchStateError(RuntimeError):
    """A profile transition would violate the workbench lifecycle contract."""


@dataclass(frozen=True)
class ProfileLaunch:
    """The sealed, secret-free handoff from the workbench to an agent adapter."""

    profile: ProfileId
    run_id: str
    client_config_path: Path
    policy_version: str


class ManagedAgentAdapter(Protocol):
    """Owns installed-agent and MCP process start/stop inside management."""

    def launch(self, launch: ProfileLaunch) -> object: ...

    def close(self, handle: object) -> None: ...

    def list_tools(self, handle: object) -> Mapping[str, Collection[str]]: ...


class SessionCredentialBroker(Protocol):
    """Keeps model and service credentials out of agent-visible configuration."""

    def prepare(
        self, profile: ProfileId, run_id: str, aliases: tuple[str, ...]
    ) -> None: ...

    def destroy(self, profile: ProfileId, run_id: str) -> None: ...


@dataclass
class _ActiveProfile:
    """Track cleanup proof for the single process compartment owned by the runtime."""

    launch: ProfileLaunch
    handle: object
    agent_closed: bool = False
    credentials_destroyed: bool = False
    config_removed: bool = False


class WorkbenchRuntime:
    """Run one profile at a time and retain its existing scenario correlation."""

    def __init__(
        self,
        session_manager: ScenarioSession,
        adapter: ManagedAgentAdapter,
        run_store: RunStorageBackend,
        *,
        payload_root: Path,
        generated_config_dir: Path,
        credential_broker: SessionCredentialBroker,
    ) -> None:
        self._session_manager = session_manager
        self._adapter = adapter
        self._run_store = run_store
        self._payload_root = payload_root
        self._generated_config_dir = generated_config_dir
        self._credential_broker = credential_broker
        self._current: _ActiveProfile | None = None

    @property
    def current_launch(self) -> ProfileLaunch | None:
        """Expose only non-secret state for the participant browser projection."""
        return self._current.launch if self._current is not None else None

    def start(self, profile: ProfileId | str) -> ProfileLaunch:
        """Launch the selected compartment for the active scenario trace."""
        if self._current is not None:
            raise WorkbenchStateError("a participant profile is already running")
        selected = profile_for(profile)
        run_id = self._active_trace_id()
        self._credential_broker.prepare(
            selected.profile_id, run_id, selected.credential_aliases
        )
        try:
            config_path = render_profile_config(
                profile=selected.profile_id,
                payload_root=self._payload_root,
                output_dir=self._generated_config_dir,
                run_id=run_id,
                credential_aliases=selected.credential_aliases,
            )
        except Exception:
            self._credential_broker.destroy(selected.profile_id, run_id)
            raise
        launch = ProfileLaunch(
            profile=selected.profile_id,
            run_id=run_id,
            client_config_path=config_path,
            policy_version=selected.policy_version,
        )
        try:
            handle = self._adapter.launch(launch)
        except Exception:
            try:
                self._credential_broker.destroy(selected.profile_id, run_id)
            finally:
                self._remove_generated_config(launch)
            self._record("agent_start_failed", launch)
            raise
        self._current = _ActiveProfile(launch, handle)
        try:
            verify_profile_tool_inventory(
                launch.profile, self._adapter.list_tools(handle)
            )
        except Exception as exc:
            self._record("inventory_failed", launch)
            try:
                self.close()
            except WorkbenchStateError as cleanup_error:
                raise WorkbenchStateError(
                    "MCP tool inventory verification failed and cleanup remains incomplete"
                ) from cleanup_error
            raise WorkbenchStateError("MCP tool inventory verification failed") from exc
        self._record("started", launch)
        return launch

    def switch(self, profile: ProfileId | str) -> ProfileLaunch:
        """Perform a purple transition by closing before starting another profile."""
        selected = profile_for(profile)
        if self._current is not None:
            self.close()
        return self.start(selected.profile_id)

    def close(self) -> None:
        """Close the current profile; a failed cleanup blocks any replacement."""
        if self._current is None:
            raise WorkbenchStateError("no participant profile is running")
        active = self._current
        cleanup_error: Exception | None = None
        if not active.agent_closed:
            try:
                self._adapter.close(active.handle)
            except Exception as exc:
                self._record("teardown_failed", active.launch)
                cleanup_error = exc
            else:
                active.agent_closed = True
        if not active.credentials_destroyed:
            try:
                self._credential_broker.destroy(
                    active.launch.profile, active.launch.run_id
                )
            except Exception as exc:
                self._record("credential_teardown_failed", active.launch)
                cleanup_error = cleanup_error or exc
            else:
                active.credentials_destroyed = True
        config_error = self._cleanup_generated_config(active)
        cleanup_error = cleanup_error or config_error
        if cleanup_error is not None:
            raise WorkbenchStateError(
                "participant profile cleanup failed"
            ) from cleanup_error
        self._record("stopped", active.launch)
        self._current = None

    def _active_trace_id(self) -> str:
        session = self._session_manager.get_active()
        if session is None or not session.trace_id:
            raise WorkbenchStateError("an active scenario with a trace id is required")
        return session.trace_id

    def _record(self, event: str, launch: ProfileLaunch) -> None:
        self._run_store.append_jsonl(
            launch.run_id,
            "workbench/events.jsonl",
            [
                {
                    "event": event,
                    "profile": launch.profile.value,
                    "policy_version": launch.policy_version,
                    "run_id": launch.run_id,
                }
            ],
        )

    def _remove_generated_config(self, launch: ProfileLaunch) -> None:
        generated_root = self._generated_config_dir.resolve()
        if launch.client_config_path.parent.resolve() != generated_root:
            raise OSError("generated configuration escaped its managed directory")
        os.unlink(launch.client_config_path)

    def _cleanup_generated_config(self, active: _ActiveProfile) -> OSError | None:
        """Remove managed client configuration and retain incomplete-cleanup state."""
        if active.config_removed:
            return None
        try:
            self._remove_generated_config(active.launch)
        except OSError as exc:
            self._record("config_teardown_failed", active.launch)
            return exc
        active.config_removed = True
        return None
