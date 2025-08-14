#!/usr/bin/env node
console.error(`[MCP-Blue] Current working directory: ${process.cwd()}`);
// SPDX-License-Identifier: BUSL-1.1

/**
 * APTL Wazuh Blue Team MCP Server
 * 
 * Provides AI agents with secure access to Wazuh SIEM operations
 * in the APTL (Advanced Purple Team Lab) environment.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { loadConfig, validateQueryParams, validateRuleXML, type WazuhConfig } from './config.js';
import { WazuhAPIClient, WazuhIndexerClient, type AlertQuery, type LogQuery } from './wazuh-client.js';

// Global configuration and clients
let config: WazuhConfig;
let wazuhAPI: WazuhAPIClient;
let indexerClient: WazuhIndexerClient;

// Initialize configuration and clients
async function initialize() {
  try {
    config = await loadConfig();
    wazuhAPI = new WazuhAPIClient(config);
    indexerClient = new WazuhIndexerClient(config);
    console.error(`[MCP-Blue] Initialized with server: ${config.mcp.server_name}`);
  } catch (error) {
    console.error('[MCP-Blue] Failed to initialize:', error);
    process.exit(1);
  }
}

/**
 * Create MCP server with tools for Wazuh SIEM operations
 */
const server = new Server(
  {
    name: 'wazuh-blue-team',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

/**
 * Handler that lists available tools for blue team operations
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'wazuh_info',
        description: 'Get information about the Wazuh SIEM stack in the lab',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'query_alerts',
        description: 'Search processed Wazuh alerts with filters',
        inputSchema: {
          type: 'object',
          properties: {
            time_range: {
              type: 'string',
              enum: ['15m', '1h', '6h', '24h', '7d'],
              description: 'Time range for the search'
            },
            min_level: {
              type: 'number',
              minimum: 1,
              maximum: 15,
              description: 'Minimum alert level to include'
            },
            source_ip: {
              type: 'string',
              description: 'Filter by source IP address'
            },
            rule_id: {
              type: 'string',
              description: 'Filter by specific rule ID'
            }
          }
        }
      },
      {
        name: 'query_logs',
        description: 'Search raw log data before rule processing',
        inputSchema: {
          type: 'object',
          properties: {
            time_range: {
              type: 'string',
              enum: ['15m', '1h', '6h', '24h', '7d'],
              description: 'Time range for the search'
            },
            search_term: {
              type: 'string',
              description: 'Search term to find in log messages'
            },
            source_ip: {
              type: 'string',
              description: 'Filter by source IP address'
            },
            log_level: {
              type: 'string',
              enum: ['debug', 'info', 'warn', 'error'],
              description: 'Filter by log level'
            }
          }
        }
      },
      {
        name: 'create_detection_rule',
        description: 'Create custom Wazuh detection rule',
        inputSchema: {
          type: 'object',
          properties: {
            rule_xml: {
              type: 'string',
              description: 'Complete XML rule definition'
            },
            rule_description: {
              type: 'string',
              description: 'Human-readable description of the rule'
            },
            rule_level: {
              type: 'number',
              minimum: 1,
              maximum: 15,
              description: 'Severity level for the rule'
            }
          },
          required: ['rule_xml']
        }
      }
    ],
  };
});

/**
 * Handler for executing tools
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;


  switch (name) {
    case 'wazuh_info': {
      try {
        const managerInfo = await wazuhAPI.getManagerInfo();
        const clusterHealth = await indexerClient.getClusterHealth();
        
        const info = {
          manager: {
            version: managerInfo.data.version,
            status: 'active',
            api_port: config.wazuh.manager.api_port,
            host: config.wazuh.manager.host
          },
          indexer: {
            cluster_health: clusterHealth.status,
            api_port: config.wazuh.indexer.port,
            host: config.wazuh.indexer.host,
            indices: ['wazuh-alerts-*', 'wazuh-archives-*']
          },
          dashboard: {
            url: config.wazuh.dashboard.url,
            api_port: config.wazuh.dashboard.port,
            host: config.wazuh.dashboard.host
          },
          lab_network: config.network.lab_subnet
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(info, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error getting Wazuh info'
              }, null, 2),
            },
          ],
        };
      }
    }

    case 'query_alerts': {
      const params = args as AlertQuery;
      
      // Validate parameters
      const validation = validateQueryParams(params, config);
      if (!validation.valid) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                error: validation.error
              }, null, 2),
            },
          ],
        };
      }

      try {
        const results = await indexerClient.searchAlerts(params);
        
        // Log blue team activity
        await logBlueTeamActivity({
          operation: 'query_alerts',
          parameters: params,
          results_count: results.count,
          timestamp: new Date().toISOString()
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: true,
                alert_count: results.count,
                alerts: results.data,
                query_params: params
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
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error querying alerts'
              }, null, 2),
            },
          ],
        };
      }
    }

    case 'query_logs': {
      const params = args as LogQuery;
      
      // Validate parameters
      const validation = validateQueryParams(params, config);
      if (!validation.valid) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                error: validation.error
              }, null, 2),
            },
          ],
        };
      }

      try {
        const results = await indexerClient.searchLogs(params);
        
        // Log blue team activity
        await logBlueTeamActivity({
          operation: 'query_logs',
          parameters: params,
          results_count: results.count,
          timestamp: new Date().toISOString()
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: true,
                log_count: results.count,
                logs: results.data,
                query_params: params
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
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error querying logs'
              }, null, 2),
            },
          ],
        };
      }
    }

    case 'create_detection_rule': {
      const { rule_xml, rule_description, rule_level } = args as {
        rule_xml: string;
        rule_description?: string;
        rule_level?: number;
      };

      // Validate rule XML
      const validation = validateRuleXML(rule_xml);
      if (!validation.valid) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                error: validation.error
              }, null, 2),
            },
          ],
        };
      }

      try {
        const result = await wazuhAPI.createRule(rule_xml, 'aptl_custom_rules.xml');
        
        // Log blue team activity
        await logBlueTeamActivity({
          operation: 'create_detection_rule',
          parameters: { rule_description, rule_level },
          results_count: 1,
          timestamp: new Date().toISOString()
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: true,
                rule_file: 'aptl_custom_rules.xml',
                restart_required: true,
                message: 'Detection rule created. Manager restart needed to activate.',
                wazuh_response: result
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
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error creating rule'
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
 * Log blue team activity for audit trail
 */
async function logBlueTeamActivity(activity: {
  operation: string;
  parameters: any;
  results_count: number;
  timestamp: string;
}): Promise<void> {
  try {
    console.error(`[MCP-Blue] Activity: ${JSON.stringify(activity)}`);
  } catch (error) {
    console.error('[MCP-Blue] Failed to log activity:', error);
  }
}

/**
 * Start the server using stdio transport
 */
async function main() {
  await initialize();
  
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[MCP-Blue] Wazuh Blue Team server running on stdio');
}

main().catch((error) => {
  console.error('[MCP-Blue] Fatal error:', error);
  process.exit(1);
});