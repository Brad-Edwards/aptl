"""Console runtime: orchestrates a single agent turn for a session.

Responsibilities:

* assemble the toolset for a session — scratchpad tools (shared memory) plus
  the MCP tools the session is allowed to reach;
* build a role-aware system prompt;
* drive the selected provider and stream its events;
* persist the user message and the final assistant message.

The runtime holds no per-turn state of its own, so a single instance is safe
to reuse across requests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterator, Optional

from aptl.console.mcp_bridge import open_mcp_toolset
from aptl.console.models import (
    ChatMessage,
    ConsoleState,
    ProviderStatus,
    Role,
    Session,
)
from aptl.console.providers import AgentProvider, select_provider
from aptl.console.registry import McpRegistry, load_registry
from aptl.console.store import ConsoleStore
from aptl.console.tools import Tool, build_scratchpad_tools
from aptl.utils.logging import get_logger

log = get_logger("console.runtime")

StreamEvent = dict[str, Any]

_ROLE_BRIEF = {
    Role.RED: (
        "You are the RED side: an offensive operator in a controlled purple-team "
        "lab. Plan and execute attacks against the lab's target stack using only "
        "the tools you are given. Narrate what you do and why."
    ),
    Role.BLUE: (
        "You are the BLUE side: a SOC analyst/defender in a controlled purple-team "
        "lab. Investigate telemetry, hunt threats, and manage cases using only the "
        "tools you are given. Narrate your reasoning."
    ),
    Role.PURPLE: (
        "You are a PURPLE-team operator with access to both offensive and "
        "defensive tools in a controlled lab. Coordinate attack and defense and "
        "explain detections as you go."
    ),
    Role.NEUTRAL: (
        "You are an operator exploring a controlled purple-team lab with the tools "
        "you are given."
    ),
}


class ConsoleRuntime:
    """Coordinates store, registry, provider, and tools for a project."""

    def __init__(
        self,
        project_dir: Path,
        *,
        store: Optional[ConsoleStore] = None,
        registry: Optional[McpRegistry] = None,
        provider: Optional[AgentProvider] = None,
    ) -> None:
        self._project_dir = project_dir
        self._store = store or ConsoleStore.for_project(project_dir)
        self._registry = registry or load_registry(project_dir)
        self._provider = provider or select_provider()

    @property
    def store(self) -> ConsoleStore:
        return self._store

    @property
    def registry(self) -> McpRegistry:
        return self._registry

    def provider_status(self) -> ProviderStatus:
        return self._provider.status()

    def default_servers_for(self, role: Role) -> list[str]:
        return self._registry.default_for_role(role)

    def state(self) -> ConsoleState:
        return ConsoleState(
            sessions=self._store.list_sessions(),
            scratchpads=self._store.list_scratchpads(),
            servers=self._registry.servers,
            provider=self.provider_status(),
        )

    def _build_system_prompt(self, session: Session, tools: list[Tool]) -> str:
        brief = _ROLE_BRIEF.get(session.role, _ROLE_BRIEF[Role.NEUTRAL])
        tool_lines = "\n".join(f"- {t.name}: {t.description}" for t in tools)
        pads = [self._store.get_scratchpad(p).name for p in session.scratchpads if _exists(self._store, p)]
        pad_note = (
            f"\n\nShared scratchpads attached to this session: {', '.join(pads)}. "
            "Other sessions may read and write these — use them to hand off findings."
            if pads
            else ""
        )
        return (
            f"{brief}\n\n"
            "This is an isolated, intentionally vulnerable training lab. Stay within "
            "the lab and only use the tools listed below.\n\n"
            f"Tools available to you:\n{tool_lines or '- (none)'}"
            f"{pad_note}"
        )

    async def run_turn(self, session_id: str, user_content: str) -> AsyncIterator[StreamEvent]:
        """Run one agent turn, streaming events and persisting messages.

        Yields the provider's stream events plus a leading ``user_message``
        and a trailing ``assistant_message`` event carrying the persisted
        records (so the client can reconcile ids).
        """
        session = self._store.get_session(session_id)
        user_msg = self._store.append_message(
            session_id, ChatMessage(role="user", content=user_content)
        )
        yield {"type": "user_message", "message": user_msg.model_dump()}

        scratchpad_tools = build_scratchpad_tools(self._store, session.scratchpads)

        async with open_mcp_toolset(
            self._registry, session.mcp_servers, self._project_dir
        ) as toolset:
            for note in toolset.notes:
                yield {"type": "note", "message": note}
            tools = scratchpad_tools + toolset.tools
            system = self._build_system_prompt(session, tools)
            history = self._store.get_session(session_id).messages

            final_text = ""
            final_calls: list[dict[str, Any]] = []
            try:
                async for event in self._provider.run_turn(
                    system=system, history=history, tools=tools
                ):
                    if event.get("type") == "done":
                        final_text = event.get("text", "")
                        final_calls = event.get("tool_calls", [])
                        continue
                    yield event
            except Exception as exc:  # noqa: BLE001 — report, don't crash the stream
                log.exception("Agent turn failed: %s", exc)
                yield {"type": "error", "message": f"Agent error: {exc}"}
                final_text = final_text or f"(turn failed: {exc})"

        assistant_msg = ChatMessage(
            role="assistant",
            content=final_text,
            tool_calls=[_coerce_tool_call(c) for c in final_calls],
        )
        saved = self._store.append_message(session_id, assistant_msg)
        yield {"type": "assistant_message", "message": saved.model_dump()}
        yield {"type": "end"}


def _exists(store: ConsoleStore, pad_id: str) -> bool:
    from aptl.console.store import NotFoundError

    try:
        store.get_scratchpad(pad_id)
        return True
    except NotFoundError:
        return False


def _coerce_tool_call(data: dict[str, Any]):
    from aptl.console.models import ToolCall

    return ToolCall.model_validate(data)
