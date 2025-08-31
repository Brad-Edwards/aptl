/**
 * Generic APTL MCP Server
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
import { type LabConfig } from './config.js';
import { SSHConnectionManager } from './ssh.js';
import { generateToolDefinitions } from './tools/definitions.js';
import { generateToolHandlers, type ToolContext } from './tools/handlers.js';

/**
 * Create and configure an MCP server with the provided lab configuration
 */
export function createMCPServer(labConfig: LabConfig) {
  const sshManager = new SSHConnectionManager();
  
  // Pre-generate tools and handlers
  const cachedTools = generateToolDefinitions(labConfig.server);
  const cachedHandlers = generateToolHandlers(labConfig.server);
  
  console.error(`[MCP] Initialized ${labConfig.server.name} with lab: ${labConfig.lab.name}`);

  // Create MCP server
  const server = new Server(
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

  // Setup request handlers
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

  // Return server with start method
  return {
    async start() {
      const transport = new StdioServerTransport();
      await server.connect(transport);
      console.error(`[MCP] ${labConfig.server.description.split(' - ')[0]} server running on stdio`);
      
      // Setup graceful shutdown
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
    }
  };
}