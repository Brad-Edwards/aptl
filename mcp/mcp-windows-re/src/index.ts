#!/usr/bin/env node
console.error(`[MCP-TOPLEVEL] Current working directory: ${process.cwd()}`);

/**
 * APTL Windows Reverse Engineering MCP Server
 * 
 * Wrapper around the generic APTL MCP server using local configuration.
 */

import { createMCPServer, loadLabConfig } from 'aptl-mcp-common';
import { resolve } from 'path';

async function main() {
  try {
    // Config file is in the same directory as this script
    const configPath = resolve(new URL('.', import.meta.url).pathname, '..', 'docker-lab-config.json');
    const config = await loadLabConfig(configPath);
    const server = createMCPServer(config);
    await server.start();
  } catch (error) {
    console.error('[MCP] Fatal error:', error);
    process.exit(1);
  }
}

main();