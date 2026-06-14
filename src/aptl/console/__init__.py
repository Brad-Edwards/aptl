"""Interactive console for exploring APTL.

The console gives a local operator a multi-session chat workbench over the
lab: red and blue chat sessions are kept separate (they never share message
history), each session controls exactly which MCP servers it can reach, and
named *scratchpads* provide shared memory that any set of sessions can read
and write. See :mod:`aptl.console.runtime` for the agent loop and
:mod:`aptl.api.routers.console` for the HTTP surface.
"""

from aptl.console.models import (
    ChatMessage,
    ConsoleState,
    McpServerSpec,
    ProviderStatus,
    Role,
    Scratchpad,
    Session,
)
from aptl.console.registry import McpRegistry, load_registry
from aptl.console.runtime import ConsoleRuntime
from aptl.console.store import ConsoleStore

__all__ = [
    "ChatMessage",
    "ConsoleRuntime",
    "ConsoleState",
    "ConsoleStore",
    "McpRegistry",
    "McpServerSpec",
    "ProviderStatus",
    "Role",
    "Scratchpad",
    "Session",
    "load_registry",
]
