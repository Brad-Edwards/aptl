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
  CallToolRequest,
} from '@modelcontextprotocol/sdk/types.js';
import { type LabConfig } from './config.js';
import { SSHConnectionManager } from './ssh.js';
import { HTTPClient } from './http.js';
import { generateToolDefinitions } from './tools/definitions.js';
import { generateToolHandlers, type ToolContext } from './tools/handlers.js';
import { generateAPIToolDefinitions } from './tools/api-definitions.js';
import { generateAPIToolHandlers, type APIToolContext } from './tools/api-handlers.js';

/**
 * Create and configure an MCP server with the provided lab configuration
 */
export function createMCPServer(labConfig: LabConfig) {
  // Initialize clients based on config
  const sshManager = labConfig.containers ? new SSHConnectionManager() : null;
  const httpClient = labConfig.api ? new HTTPClient(labConfig.api) : null;
  
  // Pre-generate tools and handlers based on available capabilities
  let cachedTools: any[] = [];
  let cachedHandlers: Record<string, any> = {};
  
  if (sshManager) {
    cachedTools.push(...generateToolDefinitions(labConfig.server));
    Object.assign(cachedHandlers, generateToolHandlers(labConfig.server));
  }
  
  if (httpClient) {
    // Only include generic tools if no predefined queries exist
    const includeGeneric = !labConfig.queries || Object.keys(labConfig.queries).length === 0;
    cachedTools.push(...generateAPIToolDefinitions(labConfig.server, labConfig.queries, includeGeneric));
    Object.assign(cachedHandlers, generateAPIToolHandlers(labConfig.server, labConfig.queries, includeGeneric));
  }
  
  console.error(`[MCP] Initialized ${labConfig.server.name} with lab: ${labConfig.lab.name}`);
  console.error(`[MCP] Available capabilities: ${sshManager ? 'SSH' : ''}${sshManager && httpClient ? ' + ' : ''}${httpClient ? 'HTTP API' : ''}`);

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

  server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
    const { name, arguments: args } = request.params;
    
    const handler = cachedHandlers[name];
    if (!handler) {
      throw new Error(`Unknown tool: ${name}`);
    }

    // Determine context type based on tool name and available clients
    let context: ToolContext | APIToolContext;
    
    if (name.includes('_api_') || (labConfig.queries && Object.keys(labConfig.queries).some(q => name.endsWith(`_${q}`)))) {
      // API tool context
      if (!httpClient) {
        throw new Error('API tool requested but HTTP client not configured');
      }
      context = {
        httpClient,
        labConfig,
      } as APIToolContext;
    } else {
      // SSH tool context
      if (!sshManager) {
        throw new Error('SSH tool requested but SSH manager not configured');
      }
      context = {
        sshManager,
        labConfig,
      } as ToolContext;
    }

    return handler(args, context);
  });

  // Setup graceful shutdown handlers (once per process)
  let handlersSetup = false;
  
  // Return server with start method
  return {
    async start() {
      const transport = new StdioServerTransport();
      await server.connect(transport);
      console.error(`[MCP] ${labConfig.server.description.split(' - ')[0]} server running on stdio`);
      
      // Setup graceful shutdown only once
      if (!handlersSetup) {
        process.on('SIGINT', async () => {
          console.error('[MCP] Shutting down gracefully...');
          if (sshManager) {
            await sshManager.disconnectAll();
          }
          process.exit(0);
        });
        
        process.on('SIGTERM', async () => {
          console.error('[MCP] Shutting down gracefully...');
          if (sshManager) {
            await sshManager.disconnectAll();
          }
          process.exit(0);
        });
        
        handlersSetup = true;
      }
    }
  };
}