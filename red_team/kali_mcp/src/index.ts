#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

/**
 * APTL Kali MCP Server
 * 
 * Provides VS Code agents with secure access to Kali Linux red team operations
 * in the APTL (Advanced Purple Team Lab) environment.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import ConfigManager, { ConfigError } from './config.js';
import { KaliConnection, SSHError } from './ssh.js';

/**
 * Create MCP server with tools for Kali Linux operations
 */
const server = new Server(
  {
    name: "APTL Kali MCP Server",
    version: "0.1.0",
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
        name: "kali_info",
        description: "Get basic system information from the Kali instance",
        inputSchema: {
          type: "object",
          properties: {},
          required: []
        }
      },
      {
        name: "run_command",
        description: "Execute a command on the Kali instance",
        inputSchema: {
          type: "object",
          properties: {
            command: {
              type: "string",
              description: "Command to execute on Kali Linux"
            },
            timeout: {
              type: "number",
              description: "Timeout in seconds (default: 30)",
              default: 30
            }
          },
          required: ["command"]
        }
      },
      {
        name: "network_scan",
        description: "Perform a basic network scan using nmap",
        inputSchema: {
          type: "object",
          properties: {
            target: {
              type: "string",
              description: "Target IP or CIDR range to scan"
            },
            scan_type: {
              type: "string",
              description: "Type of scan (quick, tcp, udp, version)",
              enum: ["quick", "tcp", "udp", "version"],
              default: "quick"
            }
          },
          required: ["target"]
        }
      }
    ]
  };
});

/**
 * Handler for executing tools
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    // Initialize configuration and connection
    const configManager = ConfigManager.getInstance();
    configManager.loadConfig(); // Validates Kali is enabled
    
    const connection = KaliConnection.fromConfig();

    switch (request.params.name) {
      case "kali_info": {
        try {
          const result = await connection.executeCommand('uname -a && whoami && pwd');
          
          return {
            content: [{
              type: "text",
              text: `Kali System Information:\n\n${result.stdout.trim()}\n\nConnection successful!`
            }]
          };
        } catch (error) {
          if (error instanceof SSHError) {
            return {
              content: [{
                type: "text",
                text: `Failed to connect to Kali: ${error.message}\n\nThis is expected if the lab is not currently deployed.`
              }]
            };
          }
          throw error;
        } finally {
          await connection.disconnect();
        }
      }

      case "run_command": {
        const command = String(request.params.arguments?.command);
        const timeoutSec = Number(request.params.arguments?.timeout) || 30;
        
        if (!command) {
          throw new Error("Command is required");
        }

        try {
          const result = await connection.executeCommand(command, timeoutSec * 1000);
          
          let output = `Command: ${command}\n`;
          output += `Exit Code: ${result.code}\n\n`;
          
          if (result.stdout) {
            output += `STDOUT:\n${result.stdout}\n`;
          }
          
          if (result.stderr) {
            output += `STDERR:\n${result.stderr}\n`;
          }

          return {
            content: [{
              type: "text",
              text: output
            }]
          };
        } catch (error) {
          if (error instanceof SSHError) {
            return {
              content: [{
                type: "text",
                text: `Failed to execute command: ${error.message}\n\nThis is expected if the lab is not currently deployed.`
              }]
            };
          }
          throw error;
        } finally {
          await connection.disconnect();
        }
      }

      case "network_scan": {
        const target = String(request.params.arguments?.target);
        const scanType = String(request.params.arguments?.scan_type) || "quick";
        
        if (!target) {
          throw new Error("Target is required");
        }

        // Validate target is allowed
        if (!configManager.isTargetAllowed(target)) {
          throw new Error(`Target ${target} is not within allowed lab networks`);
        }

        // Build nmap command based on scan type
        let nmapCmd = "nmap";
        switch (scanType) {
          case "quick":
            nmapCmd += " -T4 -F";
            break;
          case "tcp":
            nmapCmd += " -sS -T4";
            break;
          case "udp":
            nmapCmd += " -sU -T4 --top-ports 100";
            break;
          case "version":
            nmapCmd += " -sV -T4";
            break;
          default:
            throw new Error(`Unknown scan type: ${scanType}`);
        }
        
        nmapCmd += ` ${target}`;

        try {
          const result = await connection.executeCommand(nmapCmd, 60000); // 60 second timeout
          
          let output = `Network Scan Results\n`;
          output += `Command: ${nmapCmd}\n`;
          output += `Target: ${target}\n`;
          output += `Scan Type: ${scanType}\n\n`;
          
          if (result.stdout) {
            output += `Results:\n${result.stdout}\n`;
          }
          
          if (result.stderr) {
            output += `Warnings/Errors:\n${result.stderr}\n`;
          }

          return {
            content: [{
              type: "text",
              text: output
            }]
          };
        } catch (error) {
          if (error instanceof SSHError) {
            return {
              content: [{
                type: "text",
                text: `Failed to perform network scan: ${error.message}\n\nThis is expected if the lab is not currently deployed.`
              }]
            };
          }
          throw error;
        } finally {
          await connection.disconnect();
        }
      }

      default:
        throw new Error(`Unknown tool: ${request.params.name}`);
    }
  } catch (error) {
    if (error instanceof ConfigError) {
      return {
        content: [{
          type: "text",
          text: `Configuration error: ${error.message}\n\nPlease ensure lab_config.json exists and Kali is enabled.`
        }]
      };
    }
    
    // Re-throw other errors for proper error handling
    throw error;
  }
});

/**
 * Start the server using stdio transport
 */
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});
