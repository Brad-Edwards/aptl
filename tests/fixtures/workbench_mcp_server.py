"""Small stdio MCP server used to prove the production inventory probe."""

from __future__ import annotations

import asyncio

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import ListToolsResult, Tool


async def list_tools(_context: object, _params: object) -> ListToolsResult:
    """Return the fixture's fixed inventory through MCP 2's handler seam."""

    return ListToolsResult(
        tools=[
            Tool(
                name="fixture_read",
                description="Read fixture state",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="fixture_write",
                description="Write fixture state",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]
    )


async def main() -> None:
    server = Server("aptl-workbench-fixture", on_list_tools=list_tools)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
