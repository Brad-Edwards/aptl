#!/usr/bin/env node
console.error(`[MCP-TOPLEVEL] Current working directory: ${process.cwd()}`);

/**
 * APTL Minetest Client MCP Server
 * 
 * Wrapper around the generic APTL MCP server using local configuration.
 */

import { createMCPServer } from 'aptl-mcp-common';
import { loadLabConfig } from './config.js';

async function main() {
  try {
    const config = await loadLabConfig();
    const server = createMCPServer(config);
    await server.start();
  } catch (error) {
    console.error('[MCP] Fatal error:', error);
    process.exit(1);
  }
}

main();