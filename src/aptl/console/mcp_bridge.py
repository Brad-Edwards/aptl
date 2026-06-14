"""Bridge from console sessions to the lab's MCP servers.

Each agent turn that wants MCP access opens short-lived stdio connections to
exactly the servers in the session's allowlist (and only those — this is the
per-session access control), discovers their tools, and exposes them to the
agent namespaced as ``<server>__<tool>``.

The ``mcp`` Python SDK is an optional dependency. If it is not installed, or
a server is not built/available, the bridge yields no tools and records a
human-readable reason rather than failing the turn — the rest of the console
(chat, scratchpads) keeps working.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from typing import Any

from aptl.console.models import McpServerSpec
from aptl.console.registry import McpRegistry
from aptl.console.tools import Tool
from aptl.utils.logging import get_logger

log = get_logger("console.mcp_bridge")

NAMESPACE_SEP = "__"


def mcp_available() -> bool:
    """True if the optional ``mcp`` SDK is importable."""
    try:
        import mcp  # noqa: F401
        from mcp.client.stdio import stdio_client  # noqa: F401

        return True
    except ImportError:
        return False


@dataclass
class McpToolset:
    """Tools discovered from the session's allowed MCP servers, plus notes.

    ``notes`` carries per-server status (e.g. "not built", "connect failed")
    so the UI/agent can explain why an expected server is missing rather than
    silently dropping it.
    """

    tools: list[Tool] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    async def aclose(self) -> None:
        await self._stack.aclose()

    # AsyncExitStack holding the live client sessions for this turn.
    _stack: Any = None


def _server_env(spec: McpServerSpec) -> dict[str, str]:
    """Environment for a spawned server: parent env overlaid with the server's
    own ``.mcp.json`` env block (which may carry the credentials it needs)."""
    env = dict(os.environ)
    env.update(spec.env)
    return env


async def build_mcp_toolset(
    registry: McpRegistry,
    allowed: list[str],
    project_dir: Any,
) -> McpToolset:
    """Open the allowed servers and return their tools (best effort).

    Caller owns the returned toolset and must ``await toolset.aclose()`` when
    the turn ends.
    """
    from contextlib import AsyncExitStack

    toolset = McpToolset()
    toolset._stack = AsyncExitStack()

    if not allowed:
        return toolset

    if not mcp_available():
        toolset.notes.append(
            "MCP SDK not installed — run `pip install -e \".[console]\"` to "
            "give sessions live MCP access."
        )
        return toolset

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    for name in allowed:
        spec = registry.get(name)
        if spec is None:
            toolset.notes.append(f"{name}: not in MCP registry")
            continue
        if not spec.available:
            toolset.notes.append(f"{name}: {spec.unavailable_reason}")
            continue
        try:
            params = StdioServerParameters(
                command=spec.command,
                args=spec.args,
                env=_server_env(spec),
                cwd=str(project_dir),
            )
            read, write = await toolset._stack.enter_async_context(stdio_client(params))
            session = await toolset._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            listed = await session.list_tools()
            for tool in listed.tools:
                toolset.tools.append(_wrap_tool(session, spec.name, tool))
        except Exception as exc:  # noqa: BLE001 — one bad server must not kill the turn
            log.warning("MCP server %s failed to start: %s", name, exc)
            toolset.notes.append(f"{name}: connection failed ({exc})")

    return toolset


def _wrap_tool(session: Any, server: str, tool: Any) -> Tool:
    namespaced = f"{server}{NAMESPACE_SEP}{tool.name}"
    schema = getattr(tool, "inputSchema", None) or {"type": "object", "properties": {}}
    description = f"[{server}] {getattr(tool, 'description', '') or tool.name}"

    async def _handler(args: dict[str, Any]) -> str:
        result = await session.call_tool(tool.name, args)
        return _stringify_result(result)

    return Tool(
        name=namespaced,
        description=description,
        input_schema=schema,
        handler=_handler,
    )


def _stringify_result(result: Any) -> str:
    """Flatten an MCP CallToolResult into plain text for the transcript."""
    parts: list[str] = []
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
        else:
            parts.append(str(item))
    body = "\n".join(parts) if parts else "(tool returned no content)"
    if getattr(result, "isError", False):
        return f"ERROR: {body}"
    return body


# Convenience so callers can `async with`.
@contextlib.asynccontextmanager
async def open_mcp_toolset(registry: McpRegistry, allowed: list[str], project_dir: Any):
    toolset = await build_mcp_toolset(registry, allowed, project_dir)
    try:
        yield toolset
    finally:
        with contextlib.suppress(Exception):
            await toolset.aclose()
