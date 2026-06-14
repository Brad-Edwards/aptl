"""Pydantic models for the APTL console.

These models double as the on-disk persistence schema (see
:mod:`aptl.console.store`) and the API wire schema (see
:mod:`aptl.api.routers.console`). The TypeScript mirror lives in
``web/src/lib/console/types.ts`` — keep the two in sync.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class Role(str, Enum):
    """Side a session plays.

    The role is a *label and a default*, not a hard boundary: it picks the
    starting set of MCP servers and the colour the UI uses, but the real
    access control is the per-session ``mcp_servers`` allowlist, which the
    operator can edit freely (e.g. give a ``purple`` session both kali and
    wazuh). ``neutral`` tags servers usable by any side.
    """

    RED = "red"
    BLUE = "blue"
    PURPLE = "purple"
    NEUTRAL = "neutral"


def _now() -> float:
    return time.time()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class McpServerSpec(BaseModel):
    """One MCP server the console can expose to a session.

    Mirrors an entry from ``.mcp.json`` plus a console-assigned ``role`` tag
    and an ``available`` flag computed from whether its launch command and
    entrypoint actually exist on disk.
    """

    name: str
    role: Role = Role.NEUTRAL
    command: str = ""
    args: list[str] = Field(default_factory=list)
    description: str = ""
    available: bool = False
    unavailable_reason: str = ""
    # Launch environment from .mcp.json (may hold credentials). Excluded from
    # serialization so secrets never reach the API/frontend — it exists only
    # for the in-process MCP bridge to spawn the server.
    env: dict[str, str] = Field(default_factory=dict, exclude=True, repr=False)


class Scratchpad(BaseModel):
    """A shared named document.

    Scratchpads are the console's shared-memory primitive: they live outside
    any single session and can be attached to as many sessions as the
    operator likes, letting red and blue (or any mix) hand notes to each
    other without sharing chat history.
    """

    id: str = Field(default_factory=lambda: _new_id("pad"))
    name: str
    content: str = ""
    created_at: float = Field(default_factory=_now)
    updated_at: float = Field(default_factory=_now)


MessageRole = Literal["user", "assistant", "system", "tool"]


class ToolCall(BaseModel):
    """A tool invocation the assistant requested during a turn."""

    id: str
    name: str
    input: dict[str, Any] = Field(default_factory=dict)
    output: str = ""
    is_error: bool = False


class ChatMessage(BaseModel):
    """A single entry in a session transcript."""

    id: str = Field(default_factory=lambda: _new_id("msg"))
    role: MessageRole
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    created_at: float = Field(default_factory=_now)


class Session(BaseModel):
    """An isolated chat with its own MCP allowlist and scratchpad bindings.

    Sessions never share ``messages`` with one another — that is the red/blue
    separation. The only cross-session channel is the set of ``scratchpads``
    they have in common.
    """

    id: str = Field(default_factory=lambda: _new_id("sess"))
    title: str = "Untitled session"
    role: Role = Role.PURPLE
    mcp_servers: list[str] = Field(default_factory=list)
    scratchpads: list[str] = Field(default_factory=list)
    messages: list[ChatMessage] = Field(default_factory=list)
    created_at: float = Field(default_factory=_now)
    updated_at: float = Field(default_factory=_now)

    def touch(self) -> None:
        self.updated_at = _now()


class ProviderStatus(BaseModel):
    """What the agent runtime can actually do right now."""

    provider: str
    model: str = ""
    live: bool = False
    detail: str = ""


class ConsoleState(BaseModel):
    """Everything the frontend needs to render the console."""

    sessions: list[Session] = Field(default_factory=list)
    scratchpads: list[Scratchpad] = Field(default_factory=list)
    servers: list[McpServerSpec] = Field(default_factory=list)
    provider: ProviderStatus


# ---- API request bodies -------------------------------------------------


class SessionCreate(BaseModel):
    title: Optional[str] = None
    role: Role = Role.PURPLE
    mcp_servers: Optional[list[str]] = None
    scratchpads: Optional[list[str]] = None


class SessionUpdate(BaseModel):
    title: Optional[str] = None
    role: Optional[Role] = None
    mcp_servers: Optional[list[str]] = None
    scratchpads: Optional[list[str]] = None


class ScratchpadCreate(BaseModel):
    name: str
    content: str = ""


class ScratchpadUpdate(BaseModel):
    name: Optional[str] = None
    content: Optional[str] = None


class MessageCreate(BaseModel):
    content: str
