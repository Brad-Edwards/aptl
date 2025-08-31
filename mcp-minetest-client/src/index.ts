#!/usr/bin/env node
console.error(`[MCP-TOPLEVEL] Current working directory: ${process.cwd()}`);

/**
 * APTL MCP Server
 * 
 * Provides AI agents with secure access to container operations
 * in the APTL (Advanced Purple Team Lab) environment.
 * Server configuration determines the specific target and capabilities.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { loadLabConfig, type LabConfig } from './config.js';
import { SSHConnectionManager } from 'aptl-mcp-common';
import { generateToolDefinitions } from './tools/definitions.js';
import { generateToolHandlers, type ToolContext } from './tools/handlers.js';

// Global configuration and SSH manager
let labConfig: LabConfig;
let sshManager: SSHConnectionManager;
let cachedTools: any[];
let cachedHandlers: Record<string, any>;

// Initialize configuration and SSH manager
async function initialize() {
  try {
    labConfig = await loadLabConfig();
    sshManager = new SSHConnectionManager();
    
    // Pre-generate tools and handlers after config is loaded
    cachedTools = generateToolDefinitions(labConfig.server);
    cachedHandlers = generateToolHandlers(labConfig.server);
    
    console.error(`[MCP] Initialized ${labConfig.server.name} with lab: ${labConfig.lab.name}`);
  } catch (error) {
    console.error('[MCP] Failed to initialize:', error);
    process.exit(1);
  }
}

/**
 * Create MCP server with configurable tools
 */
let server: Server;

// Initialize server after config is loaded
function initializeServer() {
  server = new Server(
    {
      name: labConfig.server.name,
      version: labConfig.server.version,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );
}

/**
 * Handler that lists available tools
 */
function setupRequestHandlers() {
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: cachedTools,
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
    const { name, arguments: args } = request.params;
    
    const handler = cachedHandlers[name];
    if (!handler) {
      throw new Error(`Unknown tool: ${name}`);
    }

    const context: ToolContext = {
      sshManager,
      labConfig,
    };

    return handler(args, context);
  });
}

/**
 * Handler for executing tools
 */

/**
 * Start the server using stdio transport
 */
async function main() {
  await initialize();
  initializeServer();
  setupRequestHandlers();
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[MCP] ${labConfig.server.description.split(' - ')[0]} server running on stdio`);
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