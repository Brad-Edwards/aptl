#!/usr/bin/env node
/**
 * APTL Windows Reverse Engineering MCP Server
 */
import { startServer, getLogger } from 'aptl-mcp-common';

const log = getLogger('mcp.windows-re');

startServer(import.meta.url).catch((error) => {
  log.error('Fatal error starting MCP server', error);
  process.exit(1);
});
