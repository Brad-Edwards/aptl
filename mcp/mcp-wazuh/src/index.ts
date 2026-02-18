#!/usr/bin/env node
/**
 * APTL Wazuh SIEM MCP Server
 */
import { startServer, getLogger } from 'aptl-mcp-common';

const log = getLogger('mcp.wazuh');

startServer(import.meta.url).catch((error) => {
  log.error('Fatal error starting MCP server', error);
  process.exit(1);
});
