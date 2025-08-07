#!/usr/bin/env node
console.error(`[MCP-TOPLEVEL] Current working directory: ${process.cwd()}`);
// SPDX-License-Identifier: BUSL-1.1

/**
 * APTL Kali MCP Server
 * 
 * Provides VS Code agents with secure access to Kali Linux red team operations
 * in the APTL (Advanced Purple Team Lab) environment.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { loadLabConfig, isTargetAllowed, selectCredentials, type LabConfig } from './config.js';
import { SSHConnectionManager } from './ssh.js';

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
 * Create MCP server with tools for Kali Linux operations
 */
const server = new Server(
  {
    name: 'kali-red-team',
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
    tools: [
      {
        name: 'kali_info',
        description: 'Get information about the Kali Linux instance in the lab',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'run_command',
        description: 'Execute a command on a target instance in the lab',
        inputSchema: {
          type: 'object',
          properties: {
            target: {
              type: 'string',
              description: 'Target IP address or hostname',
            },
            command: {
              type: 'string',
              description: 'Command to execute',
            },
            username: {
              type: 'string',
              description: 'SSH username (optional, will auto-detect)',
              default: 'kali',
            },
          },
          required: ['target', 'command'],
        },
      },
    ],
  };
});

/**
 * Handler for executing tools
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'kali_info': {
      if (!('enabled' in labConfig.instances.kali) || !labConfig.instances.kali.enabled) {
        return {
          content: [
            {
              type: 'text',
              text: 'Kali instance is not enabled in the current lab configuration.',
            },
          ],
        };
      }

      const kaliInstance = labConfig.instances.kali;
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              public_ip: kaliInstance.public_ip,
              private_ip: kaliInstance.private_ip,
              ssh_user: kaliInstance.ssh_user,
              instance_type: kaliInstance.instance_type,
              lab_name: labConfig.lab.name,
              vpc_cidr: labConfig.network.vpc_cidr,
            }, null, 2),
          },
        ],
      };
    }

    case 'run_command': {
      const { target, command, username = 'kali' } = args as {
        target: string;
        command: string;
        username?: string;
      };

      try {
        // Determine which instance to use for SSH key
        const credentials = selectCredentials(target, labConfig, username);

        const result = await sshManager.executeCommand(
          target,
          credentials.username,
          credentials.sshKey,
          command,
          credentials.port
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                target,
                command,
                username: credentials.username,
                success: true,
                output: result,
              }, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                target,
                command,
                username,
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error',
              }, null, 2),
            },
          ],
        };
      }
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

/**
 * Start the server using stdio transport
 */
async function main() {
  await initialize();
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[MCP] Kali Red Team server running on stdio');
}

main().catch((error) => {
  console.error('[MCP] Fatal error:', error);
  process.exit(1);
});
