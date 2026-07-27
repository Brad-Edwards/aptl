"""Bounded decision-only adapter for an installed Codex CLI."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path

from aptl.utils.placeholders import contains_placeholder
from aptl.workbench.agent import _admitted_executable, _prepare_work_dir
from aptl.workbench.process import (
    AgentExecutionError,
    BoundedProcessRunner,
    ProcessRunner,
)
from aptl.workbench.runtime import AgentLaunch, DecisionAgentLaunch

_MODEL_CREDENTIAL = "CODEX_API_KEY"
_BASE_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "NO_COLOR": "1",
}


@dataclass
class _CodexHandle:
    """Represent CodexHandle state."""

    launch: DecisionAgentLaunch
    environment: dict[str, str]
    ready: bool = False
    closed: bool = False


class CodexManagedAgentAdapter:
    """Invoke Codex in an empty, read-only, ephemeral decision compartment."""

    def __init__(
        self,
        *,
        codex_executable: Path,
        work_dir: Path,
        runner: ProcessRunner | None = None,
        timeout_seconds: float = 120.0,
        max_output_bytes: int = 1_000_000,
        max_prompt_chars: int = 64_000,
    ) -> None:
        """Initialize an admitted Codex executable in an ephemeral home."""

        if timeout_seconds <= 0 or max_output_bytes <= 0 or max_prompt_chars <= 0:
            raise AgentExecutionError("agent limits are invalid")
        self._executable = _admitted_executable(codex_executable)
        self._work_dir = _prepare_work_dir(work_dir)
        self._codex_home = _prepare_work_dir(self._work_dir / "codex-home")
        self._runner = runner or BoundedProcessRunner()
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._max_prompt_chars = max_prompt_chars

    def launch(
        self,
        launch: AgentLaunch,
        credentials: Mapping[str, str],
    ) -> object:
        """Create a decision-only handle backed by a minimal credential lease."""

        if not isinstance(launch, DecisionAgentLaunch):
            raise AgentExecutionError("Codex adapter supports decision-only launches")
        credential = credentials.get(_MODEL_CREDENTIAL)
        if not credential or contains_placeholder(credential):
            raise AgentExecutionError("agent credential lease is incomplete")
        environment = {
            **_BASE_ENVIRONMENT,
            "CODEX_HOME": str(self._codex_home),
            _MODEL_CREDENTIAL: credential,
        }
        return _CodexHandle(launch=launch, environment=environment)

    @staticmethod
    def list_tools(
        handle: object,
    ) -> Mapping[str, Collection[str]]:
        """Expose the intentionally empty action-tool inventory."""

        active = _require_handle(handle)
        if active.closed:
            raise AgentExecutionError("agent profile is closed")
        active.ready = True
        return {}

    def respond(self, handle: object, message: str) -> str:
        """Obtain one bounded structured decision from the installed provider."""

        active = _require_handle(handle)
        if active.closed or not active.ready:
            raise AgentExecutionError("agent profile is not ready")
        if not message or len(message) > self._max_prompt_chars:
            raise AgentExecutionError(
                "participant message exceeds the configured limit"
            )
        result = self._runner.run(
            self._argv(self._executable),
            env=dict(active.environment),
            cwd=self._work_dir,
            stdin=message.encode(),
            timeout_seconds=self._timeout_seconds,
            max_output_bytes=self._max_output_bytes,
        )
        if result.returncode != 0:
            raise AgentExecutionError("agent request failed")
        return _parse_codex_result(result.stdout)

    @staticmethod
    def close(handle: object) -> None:
        """Destroy the handle's credential-bearing environment."""

        active = _require_handle(handle)
        active.environment.clear()
        active.ready = False
        active.closed = True

    @staticmethod
    def _argv(executable: Path) -> tuple[str, ...]:
        """Build the tool-disabled Codex invocation."""

        return (
            str(executable),
            "exec",
            "--disable",
            "shell_tool",
            "--disable",
            "unified_exec",
            "--disable",
            "code_mode_host",
            "--disable",
            "browser_use",
            "--disable",
            "computer_use",
            "--disable",
            "apps",
            "--disable",
            "multi_agent",
            "--disable",
            "image_generation",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--ephemeral",
            "--color",
            "never",
            "--json",
            "-",
        )


def _require_handle(handle: object) -> _CodexHandle:
    """Handle handle for the bounded participant workflow."""
    if not isinstance(handle, _CodexHandle):
        raise AgentExecutionError("unknown agent handle")
    return handle


def _parse_codex_result(stdout: bytes) -> str:
    """Return the last completed agent message from Codex JSONL."""

    final_message: str | None = None
    try:
        for raw_line in stdout.decode("utf-8").splitlines():
            payload = json.loads(raw_line)
            item = payload.get("item")
            if (
                payload.get("type") == "item.completed"
                and isinstance(item, Mapping)
                and item.get("type") == "agent_message"
                and isinstance(item.get("text"), str)
                and item["text"]
            ):
                final_message = item["text"]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentExecutionError("agent returned an invalid result") from exc
    if final_message is None:
        raise AgentExecutionError("agent returned an invalid result")
    return final_message


__all__ = ("CodexManagedAgentAdapter",)
