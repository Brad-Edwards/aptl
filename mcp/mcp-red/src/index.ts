#!/usr/bin/env node
/**
 * APTL Kali Red Team MCP Server
 */
import { startServer, getLogger } from 'aptl-mcp-common';

const log = getLogger('mcp.red');

startServer(import.meta.url).catch((error) => {
  log.error('Fatal error starting MCP server', error);
  process.exit(1);
});
