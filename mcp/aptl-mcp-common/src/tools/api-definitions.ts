import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { LabConfig } from '../config.js';

export function generateAPIToolDefinitions(
  serverConfig: LabConfig['server'], 
  queries?: LabConfig['queries'],
  includeGenericTools: boolean = true
): Tool[] {
  const tools: Tool[] = [];
  
  if (includeGenericTools) {
    tools.push(
      // Generic API call tool
      {
        name: `${serverConfig.toolPrefix}_api_call`,
      description: `Make arbitrary API call to ${serverConfig.targetName}`,
      inputSchema: {
        type: 'object',
        properties: {
          endpoint: {
            type: 'string',
            description: 'API endpoint path (e.g., /api/alerts)',
          },
          method: {
            type: 'string',
            enum: ['GET', 'POST', 'PUT', 'DELETE'],
            default: 'GET',
            description: 'HTTP method',
          },
          params: {
            type: 'object',
            description: 'Query parameters as key-value pairs',
          },
          body: {
            type: 'object',
            description: 'Request body for POST/PUT requests',
          },
          headers: {
            type: 'object',
            description: 'Additional headers as key-value pairs',
          },
          response_type: {
            type: 'string',
            enum: ['json', 'text'],
            default: 'json',
            description: 'Expected response type',
          },
        },
        required: ['endpoint'],
      },
    },

      // API info tool
      {
        name: `${serverConfig.toolPrefix}_api_info`,
        description: `Get ${serverConfig.targetName} API connection information`,
        inputSchema: {
          type: 'object',
          properties: {},
        },
      }
    );
  }

  // Add predefined query tools
  if (queries) {
    Object.entries(queries).forEach(([queryName, queryConfig]) => {
      tools.push({
        name: `${serverConfig.toolPrefix}_${queryName}`,
        description: queryConfig.description,
        inputSchema: {
          type: 'object',
          properties: {
            // Allow overriding any template parameters
            params: {
              type: 'object',
              description: 'Override or add query parameters',
            },
            body: {
              type: 'object', 
              description: 'Override or add request body data',
            },
          },
          required: [],
        },
      });
    });
  }

  return tools;
}