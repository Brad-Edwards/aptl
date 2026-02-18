#!/usr/bin/env node
/**
 * APTL Case Management MCP Server
 */
import { startServer, getLogger } from 'aptl-mcp-common';

const log = getLogger('mcp.casemgmt');

startServer(import.meta.url).catch((error) => {
  log.error('Fatal error starting MCP server', error);
  process.exit(1);
});
