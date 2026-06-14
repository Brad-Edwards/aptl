"""Agent tools the console exposes to a session.

Two families of tools exist:

* **Scratchpad tools** (this module) — the shared-memory primitive. They are
  always available, need no external services, and operate on the
  :class:`~aptl.console.store.ConsoleStore`, scoped to the scratchpads
  attached to the calling session. This is what lets a red session drop a
  finding that a blue session picks up.
* **MCP tools** — proxied from the lab's MCP servers, gated by the session's
  ``mcp_servers`` allowlist (see :mod:`aptl.console.mcp_bridge`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from aptl.console.store import ConsoleStore, NotFoundError

# A tool handler takes the parsed input object and returns text output.
ToolHandler = Callable[[dict[str, Any]], Awaitable[str]]


@dataclass
class Tool:
    """A single callable tool offered to the agent."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


def _scratchpad_index(store: ConsoleStore, scratchpad_ids: list[str]) -> dict[str, str]:
    """Map attached scratchpad *names* to their ids (skipping deleted ones)."""
    index: dict[str, str] = {}
    for pad_id in scratchpad_ids:
        try:
            pad = store.get_scratchpad(pad_id)
        except NotFoundError:
            continue
        index[pad.name] = pad.id
    return index


def build_scratchpad_tools(store: ConsoleStore, scratchpad_ids: list[str]) -> list[Tool]:
    """Build the scratchpad toolset scoped to one session's attached pads.

    If a session has no scratchpads attached, no scratchpad tools are
    offered — there is nothing shared to act on.
    """
    if not scratchpad_ids:
        return []

    def _names() -> list[str]:
        return sorted(_scratchpad_index(store, scratchpad_ids).keys())

    async def _list(_: dict[str, Any]) -> str:
        names = _names()
        if not names:
            return "No scratchpads are attached to this session."
        lines = []
        for name in names:
            pad = store.get_scratchpad(_scratchpad_index(store, scratchpad_ids)[name])
            preview = pad.content.strip().splitlines()[:1]
            head = preview[0][:80] if preview else "(empty)"
            lines.append(f"- {name}: {head}")
        return "Shared scratchpads:\n" + "\n".join(lines)

    async def _read(args: dict[str, Any]) -> str:
        name = str(args.get("name", "")).strip()
        index = _scratchpad_index(store, scratchpad_ids)
        if name not in index:
            return f"No attached scratchpad named {name!r}. Available: {', '.join(_names()) or '(none)'}"
        pad = store.get_scratchpad(index[name])
        return pad.content if pad.content else "(scratchpad is empty)"

    async def _write(args: dict[str, Any]) -> str:
        name = str(args.get("name", "")).strip()
        content = str(args.get("content", ""))
        mode = str(args.get("mode", "overwrite")).strip().lower()
        index = _scratchpad_index(store, scratchpad_ids)
        if name not in index:
            return f"No attached scratchpad named {name!r}. Available: {', '.join(_names()) or '(none)'}"
        pad = store.get_scratchpad(index[name])
        if mode == "append":
            sep = "\n" if pad.content and not pad.content.endswith("\n") else ""
            pad.content = f"{pad.content}{sep}{content}"
        else:
            pad.content = content
        store.update_scratchpad(pad)
        return f"Wrote {len(content)} chars to scratchpad {name!r} (mode={mode})."

    return [
        Tool(
            name="scratchpad_list",
            description=(
                "List the shared scratchpads attached to this session and a "
                "one-line preview of each. Scratchpads are shared with other "
                "chat sessions — use them to hand off findings."
            ),
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            handler=_list,
        ),
        Tool(
            name="scratchpad_read",
            description="Read the full contents of a named shared scratchpad.",
            input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Scratchpad name."}
                },
                "required": ["name"],
                "additionalProperties": False,
            },
            handler=_read,
        ),
        Tool(
            name="scratchpad_write",
            description=(
                "Write to a named shared scratchpad so other sessions can see "
                "it. Use mode='append' to add without erasing existing notes."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Scratchpad name."},
                    "content": {"type": "string", "description": "Text to store."},
                    "mode": {
                        "type": "string",
                        "enum": ["overwrite", "append"],
                        "description": "overwrite (default) or append.",
                    },
                },
                "required": ["name", "content"],
                "additionalProperties": False,
            },
            handler=_write,
        ),
    ]
