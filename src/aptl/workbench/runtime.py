"""Ordered profile lifecycle for the participant workbench."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Collection, Mapping
from threading import RLock
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
    model: str


@dataclass(frozen=True)
class DecisionAgentLaunch:
    """Secret-free launch for an installed agent with no action tools."""

    provider: str
    run_id: str
    model: str
    policy_version: str = "aptl-participant-decision-provider/v1"


AgentLaunch = ProfileLaunch | DecisionAgentLaunch


@dataclass(frozen=True)
class WorkbenchPaths:
    """Trusted filesystem inputs for one workbench runtime."""

    payload_root: Path
    generated_config_dir: Path
    node_executable: Path = Path("/usr/bin/node")


class ManagedAgentAdapter(Protocol):
    """Owns installed-agent and MCP process start/stop inside management."""

    def launch(self, launch: AgentLaunch, credentials: Mapping[str, str]) -> object: ...

    def close(self, handle: object) -> None: ...

    def list_tools(self, handle: object) -> Mapping[str, Collection[str]]: ...

    def respond(
        self,
        handle: object,
        message: str,
        *,
        response_schema: Mapping[str, object] | None = None,
    ) -> str: ...


class SessionCredentialBroker(Protocol):
    """Keeps model and service credentials out of agent-visible configuration."""

    def prepare(
        self, profile: ProfileId, run_id: str, aliases: tuple[str, ...]
    ) -> Mapping[str, str]: ...

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
        paths: WorkbenchPaths,
        credential_broker: SessionCredentialBroker,
        model: str,
    ) -> None:
        self._session_manager = session_manager
        self._adapter = adapter
        self._run_store = run_store
        self._payload_root = paths.payload_root
        self._generated_config_dir = paths.generated_config_dir
        self._prepare_generated_config_parent()
        self._credential_broker = credential_broker
        self._model = model
        self._node_executable = paths.node_executable
        self._current: _ActiveProfile | None = None
        self._lock = RLock()

    def _prepare_generated_config_parent(self) -> None:
        """Establish the trusted base used by no-follow config creation."""
        parent = self._generated_config_dir.parent
        try:
            parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise WorkbenchStateError(
                "managed configuration directory is unavailable"
            ) from exc
        stat = parent.stat()
        if (
            parent.is_symlink()
            or not parent.is_dir()
            or stat.st_uid not in {0, os.getuid()}
            or stat.st_mode & 0o022
            or not os.access(parent, os.W_OK | os.X_OK)
        ):
            raise WorkbenchStateError("managed configuration directory is unavailable")

    @property
    def current_launch(self) -> ProfileLaunch | None:
        """Expose only non-secret state for the participant browser projection."""
        with self._lock:
            return self._current.launch if self._current is not None else None

    def start(self, profile: ProfileId | str) -> ProfileLaunch:
        """Launch the selected compartment for the active scenario trace."""
        with self._lock:
            return self._start(profile)

    def _start(self, profile: ProfileId | str) -> ProfileLaunch:
        if self._current is not None:
            raise WorkbenchStateError("a participant profile is already running")
        selected = profile_for(profile)
        run_id = self._active_trace_id()
        credentials = self._credential_broker.prepare(
            selected.profile_id, run_id, selected.credential_aliases
        )
        try:
            config_path = render_profile_config(
                profile=selected.profile_id,
                payload_root=self._payload_root,
                output_dir=self._generated_config_dir,
                state_dir=self._session_manager.state_dir,
                node_executable=self._node_executable,
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
            model=self._model,
        )
        try:
            handle = self._adapter.launch(launch, credentials)
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
                self._close()
            except WorkbenchStateError as cleanup_error:
                raise WorkbenchStateError(
                    "MCP tool inventory verification failed and cleanup remains incomplete"
                ) from cleanup_error
            raise WorkbenchStateError("MCP tool inventory verification failed") from exc
        self._record("started", launch)
        return launch

    def respond(self, message: str) -> str:
        """Run one participant message through the selected managed adapter."""
        with self._lock:
            return self._respond(message)

    def _respond(self, message: str) -> str:
        if self._current is None:
            raise WorkbenchStateError("no participant profile is running")
        active = self._current
        try:
            response = self._adapter.respond(active.handle, message)
        except Exception as exc:
            self._record(
                "agent_turn_failed",
                active.launch,
                {"request_sha256": _sha256_text(message)},
            )
            raise WorkbenchStateError("participant agent request failed") from exc
        self._record(
            "agent_turn",
            active.launch,
            {
                "request_sha256": _sha256_text(message),
                "response_sha256": _sha256_text(response),
                "request_chars": len(message),
                "response_chars": len(response),
            },
        )
        return response

    def switch(self, profile: ProfileId | str) -> ProfileLaunch:
        """Perform a purple transition by closing before starting another profile."""
        with self._lock:
            selected = profile_for(profile)
            if self._current is not None:
                self._close()
            return self._start(selected.profile_id)

    def close(self) -> None:
        """Close the current profile; a failed cleanup blocks any replacement."""
        with self._lock:
            self._close()

    def _close(self) -> None:
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

    def _record(
        self,
        event: str,
        launch: ProfileLaunch,
        details: Mapping[str, object] | None = None,
    ) -> None:
        record: dict[str, object] = {
            "event": event,
            "profile": launch.profile.value,
            "policy_version": launch.policy_version,
            "run_id": launch.run_id,
        }
        if details is not None:
            record.update(details)
        self._run_store.append_jsonl(
            launch.run_id,
            "workbench/events.jsonl",
            [record],
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


def _sha256_text(value: str) -> str:
    """Return the hexadecimal SHA-256 digest of UTF-8 text."""
    return hashlib.sha256(value.encode()).hexdigest()
