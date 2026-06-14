"""Agent brains for the console.

A provider turns a session's message history plus a toolset into a streamed
assistant turn. Two are shipped:

* :class:`EchoProvider` — the default. Needs no API key and no network. It is
  not an LLM: it gives a guided, deterministic experience and exposes a small
  set of slash commands (``/help``, ``/tools``, ``/run``) that *actually*
  execute the session's tools. That means scratchpad sharing and (when built)
  MCP calls work end-to-end for exploration before anyone wires up a key.
* :class:`AnthropicProvider` — a real Claude agent with tool use, activated
  when ``ANTHROPIC_API_KEY`` is set and the ``anthropic`` SDK is installed.

Both yield the same stream-event shape so the runtime and frontend do not
care which is in use.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator, Protocol

from aptl.console.models import ChatMessage, ProviderStatus, ToolCall
from aptl.console.tools import Tool
from aptl.utils.logging import get_logger

log = get_logger("console.providers")

# Stream events are plain dicts so they serialise straight to SSE.
StreamEvent = dict[str, Any]

DEFAULT_MODEL = os.environ.get("APTL_CONSOLE_MODEL", "claude-sonnet-4-6")
MAX_TOOL_ITERATIONS = 12


class AgentProvider(Protocol):
    """The brain behind a session."""

    def status(self) -> ProviderStatus: ...

    async def run_turn(
        self,
        *,
        system: str,
        history: list[ChatMessage],
        tools: list[Tool],
    ) -> AsyncIterator[StreamEvent]: ...


def _tool_map(tools: list[Tool]) -> dict[str, Tool]:
    return {t.name: t for t in tools}


class EchoProvider:
    """Deterministic, offline provider with executable slash commands."""

    name = "echo"

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            provider=self.name,
            model="(none)",
            live=False,
            detail=(
                "Demo mode — no ANTHROPIC_API_KEY set. Chat replies are "
                "scripted, but /run, /tools and scratchpad commands execute "
                "for real. Set ANTHROPIC_API_KEY for a live agent."
            ),
        )

    async def run_turn(
        self,
        *,
        system: str,
        history: list[ChatMessage],
        tools: list[Tool],
    ) -> AsyncIterator[StreamEvent]:
        user_text = _last_user_text(history)
        stripped = user_text.strip()
        if stripped.startswith("/"):
            async for event in self._handle_command(stripped, tools):
                yield event
            return

        async for event in self._guided_reply(user_text, tools):
            yield event

    async def _handle_command(
        self, text: str, tools: list[Tool]
    ) -> AsyncIterator[StreamEvent]:
        # Deliberately not shlex: the /run payload is raw JSON whose quotes
        # must survive intact. Split only the leading command word off.
        head, _, rest = text.partition(" ")
        cmd = head.lower()
        by_name = _tool_map(tools)

        if cmd in ("/help", "/?"):
            yield _token(_HELP_TEXT)
            yield _done(_HELP_TEXT)
            return

        if cmd == "/tools":
            body = _format_tools(tools)
            yield _token(body)
            yield _done(body)
            return

        if cmd == "/run":
            async for event in self._run_tool(rest.strip(), by_name):
                yield event
            return

        msg = f"Unknown command {cmd!r}. Try /help."
        yield _token(msg)
        yield _done(msg)

    async def _run_tool(
        self, rest: str, by_name: dict[str, Tool]
    ) -> AsyncIterator[StreamEvent]:
        name, _, raw_args = rest.partition(" ")
        if not name:
            msg = "Usage: /run <tool> <json-args>. See /tools for names."
            yield _token(msg)
            yield _done(msg)
            return
        tool = by_name.get(name)
        if tool is None:
            msg = f"No tool named {name!r}. Available: {', '.join(by_name) or '(none)'}"
            yield _token(msg)
            yield _done(msg)
            return
        raw = raw_args.strip() or "{}"
        try:
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("arguments must be a JSON object")
        except (json.JSONDecodeError, ValueError) as exc:
            msg = f"Could not parse arguments as JSON object: {exc}"
            yield _token(msg)
            yield _done(msg)
            return

        call_id = f"call_{name}"
        yield {"type": "tool_call", "id": call_id, "name": name, "input": parsed}
        try:
            output = await tool.handler(parsed)
            is_error = False
        except Exception as exc:  # noqa: BLE001 — surface tool failure to the user
            output = f"Tool raised: {exc}"
            is_error = True
        yield {
            "type": "tool_result",
            "id": call_id,
            "name": name,
            "output": output,
            "is_error": is_error,
        }
        summary = f"Ran `{name}`. Result:\n\n{output}"
        yield _token(summary)
        yield _done(
            summary,
            tool_calls=[ToolCall(id=call_id, name=name, input=parsed, output=output, is_error=is_error)],
        )

    async def _guided_reply(
        self, user_text: str, tools: list[Tool]
    ) -> AsyncIterator[StreamEvent]:
        tool_names = [t.name for t in tools]
        reply = (
            "**Demo mode.** I don't have a live model attached, so I can't "
            "reason about your request — but this session's tools work right "
            "now. Set `ANTHROPIC_API_KEY` to turn on a real agent.\n\n"
            f"You said: {user_text.strip() or '(nothing)'}\n\n"
            f"Tools available to this session ({len(tool_names)}): "
            f"{', '.join(tool_names) if tool_names else 'none — attach a scratchpad or enable MCP servers'}.\n\n"
            "Try `/help`, `/tools`, or e.g. "
            "`/run scratchpad_write {\"name\": \"findings\", \"content\": \"hello\"}`."
        )
        yield _token(reply)
        yield _done(reply)


class AnthropicProvider:
    """Live Claude agent with tool use over the session's toolset."""

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self._model = model

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            provider=self.name,
            model=self._model,
            live=True,
            detail=f"Live agent using {self._model} via the Anthropic API.",
        )

    async def run_turn(
        self,
        *,
        system: str,
        history: list[ChatMessage],
        tools: list[Tool],
    ) -> AsyncIterator[StreamEvent]:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic()
        by_name = _tool_map(tools)
        tool_specs = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in tools
        ]
        messages = _to_anthropic_messages(history)
        accumulated_text: list[str] = []
        accumulated_calls: list[ToolCall] = []

        for _ in range(MAX_TOOL_ITERATIONS):
            response = await client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=system,
                messages=messages,
                tools=tool_specs or None,
            )
            assistant_content: list[dict[str, Any]] = []
            tool_uses: list[Any] = []
            for block in response.content:
                if block.type == "text":
                    accumulated_text.append(block.text)
                    yield _token(block.text)
                    assistant_content.append({"type": "text", "text": block.text})
                elif block.type == "tool_use":
                    tool_uses.append(block)
                    assistant_content.append(
                        {
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        }
                    )

            messages.append({"role": "assistant", "content": assistant_content})

            if not tool_uses:
                break

            tool_results: list[dict[str, Any]] = []
            for use in tool_uses:
                yield {"type": "tool_call", "id": use.id, "name": use.name, "input": use.input}
                tool = by_name.get(use.name)
                if tool is None:
                    output, is_error = f"No such tool: {use.name}", True
                else:
                    try:
                        output, is_error = await tool.handler(dict(use.input)), False
                    except Exception as exc:  # noqa: BLE001
                        output, is_error = f"Tool raised: {exc}", True
                yield {
                    "type": "tool_result",
                    "id": use.id,
                    "name": use.name,
                    "output": output,
                    "is_error": is_error,
                }
                accumulated_calls.append(
                    ToolCall(id=use.id, name=use.name, input=dict(use.input), output=output, is_error=is_error)
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": use.id,
                        "content": output,
                        "is_error": is_error,
                    }
                )
            messages.append({"role": "user", "content": tool_results})

        yield _done("".join(accumulated_text), tool_calls=accumulated_calls)


def _to_anthropic_messages(history: list[ChatMessage]) -> list[dict[str, Any]]:
    """Project stored transcript into the Anthropic messages format.

    Only user/assistant text is replayed; stored tool-call detail stays in
    the transcript for the UI but is not re-sent (the model re-derives tool
    use from the conversation).
    """
    messages: list[dict[str, Any]] = []
    for msg in history:
        if msg.role not in ("user", "assistant"):
            continue
        if not msg.content.strip():
            continue
        messages.append({"role": msg.role, "content": msg.content})
    return messages


def _last_user_text(history: list[ChatMessage]) -> str:
    for msg in reversed(history):
        if msg.role == "user":
            return msg.content
    return ""


def _token(text: str) -> StreamEvent:
    return {"type": "token", "text": text}


def _done(text: str, tool_calls: list[ToolCall] | None = None) -> StreamEvent:
    return {
        "type": "done",
        "text": text,
        "tool_calls": [tc.model_dump() for tc in (tool_calls or [])],
    }


def select_provider() -> AgentProvider:
    """Pick the live provider if configured, else the offline echo provider."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa: F401

            return AnthropicProvider()
        except ImportError:
            log.warning(
                "ANTHROPIC_API_KEY is set but the 'anthropic' package is not "
                "installed; falling back to demo mode. Run "
                'pip install -e ".[console]".'
            )
    return EchoProvider()


_HELP_TEXT = (
    "**Console demo mode commands**\n\n"
    "- `/help` — this message\n"
    "- `/tools` — list tools available to this session\n"
    "- `/run <tool> <json-args>` — execute a tool, e.g. "
    "`/run scratchpad_list {}`\n\n"
    "Scratchpad tools appear when you attach a scratchpad; MCP tools appear "
    "when you enable available MCP servers for this session. Set "
    "`ANTHROPIC_API_KEY` for a live agent that calls these tools for you."
)


def _format_tools(tools: list[Tool]) -> str:
    if not tools:
        return (
            "No tools available to this session. Attach a scratchpad for "
            "shared-memory tools, or enable MCP servers in the access panel."
        )
    lines = ["Tools available to this session:\n"]
    for tool in tools:
        lines.append(f"- `{tool.name}` — {tool.description}")
    return "\n".join(lines)
