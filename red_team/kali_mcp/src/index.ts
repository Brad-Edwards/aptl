#!/usr/bin/env node
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
import { loadLabConfig, isTargetAllowed, type LabConfig } from './config.js';
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

      // Validate target is allowed
      if (!isTargetAllowed(target, labConfig.mcp.allowed_targets)) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: Target ${target} is not in allowed network ranges: ${labConfig.mcp.allowed_targets.join(', ')}`,
            },
          ],
        };
      }

      try {
        // Determine which instance to use for SSH key
        let sshKey: string;
        let actualUsername: string;

        // Auto-detect instance and credentials
        if (labConfig.instances.siem.public_ip === target || labConfig.instances.siem.private_ip === target) {
          sshKey = labConfig.instances.siem.ssh_key;
          actualUsername = labConfig.instances.siem.ssh_user;
        } else if (labConfig.instances.victim.public_ip === target || labConfig.instances.victim.private_ip === target) {
          sshKey = labConfig.instances.victim.ssh_key;
          actualUsername = labConfig.instances.victim.ssh_user;
        } else if ('ssh_key' in labConfig.instances.kali && 
                   (labConfig.instances.kali.public_ip === target || labConfig.instances.kali.private_ip === target)) {
          sshKey = labConfig.instances.kali.ssh_key;
          actualUsername = labConfig.instances.kali.ssh_user;
        } else {
          // Default to Kali credentials for unknown targets in allowed ranges
          if (!('ssh_key' in labConfig.instances.kali)) {
            throw new Error('Kali instance not available for SSH operations');
          }
          sshKey = labConfig.instances.kali.ssh_key;
          actualUsername = username;
        }

        const result = await sshManager.executeCommand(
          target,
          actualUsername,
          sshKey,
          command
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                target,
                command,
                username: actualUsername,
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
