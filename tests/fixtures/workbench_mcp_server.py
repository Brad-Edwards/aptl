"""Small stdio MCP server used to prove the production inventory probe."""

from __future__ import annotations

import asyncio

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool


async def main() -> None:
    server = Server("aptl-workbench-fixture")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
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

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
