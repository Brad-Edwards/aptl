#!/usr/bin/env node
/**
 * APTL Wazuh SIEM MCP Server
 */
import { startServer } from 'aptl-mcp-common';

try {
  await startServer(import.meta.url);
} catch (error) {
  console.error('[MCP] Fatal error:', error);
  process.exit(1);
}
