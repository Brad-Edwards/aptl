#!/usr/bin/env node
console.error(`[MCP-TOPLEVEL] Current working directory: ${process.cwd()}`);

/**
 * APTL Minetest Server MCP Server
 * 
 * Provides VS Code agents with secure access to Minetest server container operations
 * in the APTL (Advanced Purple Team Lab) environment.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { loadLabConfig, type LabConfig } from './config.js';
import { SSHConnectionManager } from 'aptl-mcp-common';
import { toolDefinitions } from './tools/definitions.js';
import { toolHandlers, type ToolContext } from './tools/handlers.js';

// Global configuration and SSH manager
let labConfig: LabConfig;
let sshManager: SSHConnectionManager;

// Initialize configuration and SSH manager
async function initialize() {
  try {
    labConfig = await loadLabConfig();
    sshManager = new SSHConnectionManager();
    console.error(`[MCP] Initialized with lab: ${labConfig.lab.name}`);
  } catch (error) {
    console.error('[MCP] Failed to initialize:', error);
    process.exit(1);
  }
}

/**
 * Create MCP server with tools for Minetest server operations
 */
const server = new Server(
  {
    name: 'minetest-server-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

/**
 * Handler that lists available tools for red team operations
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: toolDefinitions,
  };
});

/**
 * Handler for executing tools
 */
server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
  const { name, arguments: args } = request.params;
  
  const handler = toolHandlers[name];
  if (!handler) {
    throw new Error(`Unknown tool: ${name}`);
  }

  const context: ToolContext = {
    sshManager,
    labConfig,
  };

  return handler(args, context);
});

/**
 * Start the server using stdio transport
 */
async function main() {
  await initialize();
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[MCP] Minetest Server MCP server running on stdio');
}

process.on('SIGINT', async () => {
  console.error('[MCP] Shutting down gracefully...');
  await sshManager.disconnectAll();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.error('[MCP] Shutting down gracefully...');
  await sshManager.disconnectAll();
  process.exit(0);
});

main().catch((error) => {
  console.error('[MCP] Fatal error:', error);
  process.exit(1);
});