#!/usr/bin/env node
/**
 * APTL Indexer MCP Server
 * Minimal server: raw ES DSL queries + detection rule writing
 */
import { startServer } from 'aptl-mcp-common';

try {
  await startServer(import.meta.url);
} catch (error) {
  console.error('[MCP] Fatal error:', error);
  process.exit(1);
}
