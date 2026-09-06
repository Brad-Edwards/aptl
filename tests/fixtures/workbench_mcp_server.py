"""Small stdio MCP server used to prove the production inventory probe."""

from __future__ import annotations

import asyncio

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import ListToolsResult, PaginatedRequestParams, Tool
from mcp.server.context import ServerRequestContext


async def main() -> None:
    async def list_tools(
        _context: ServerRequestContext[object],
        _params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        return ListToolsResult(tools=[
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
        ])

    server = Server("aptl-workbench-fixture", on_list_tools=list_tools)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
