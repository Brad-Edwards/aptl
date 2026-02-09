import { HTTPClient } from '../http.js';
import { LabConfig } from '../config.js';

export interface APIToolContext {
  httpClient: HTTPClient;
  labConfig: LabConfig;
}

// Argument interfaces for API handlers
interface APICallArgs {
  endpoint: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  params?: Record<string, unknown>;
  body?: unknown;
  headers?: Record<string, string>;
  response_type?: 'json' | 'text';
}

interface APIInfoArgs {}

interface PredefinedQueryArgs {
  params?: Record<string, unknown>;
  body?: Record<string, unknown>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- MCP SDK provides untyped args; validated by JSON Schema before reaching handlers
export type APIToolHandler = (args: any, context: APIToolContext) => Promise<{ content: { type: string; text: string }[] }>;

// Base API handler functions — each casts args to its specific interface.
// MCP SDK validates args against the JSON Schema before handlers run.
const baseAPIHandlers = {
  api_call: async (args: APICallArgs, { httpClient }: APIToolContext) => {
    const {
      endpoint,
      method = 'GET',
      params,
      body,
      headers,
      response_type = 'json'
    } = args;

    try {
      const result = await httpClient.makeRequest(endpoint, method, {
        params,
        body,
        headers,
        responseType: response_type,
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              method,
              endpoint,
              status: result.status,
              data: result.data,
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
              method,
              endpoint,
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },

  api_info: async (_args: APIInfoArgs, { labConfig }: APIToolContext) => {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            target_name: labConfig.server.targetName,
            lab_name: labConfig.lab.name,
            lab_network: labConfig.lab.network_subnet,
            api_base_url: labConfig.api?.baseUrl || 'Not configured',
            available_queries: labConfig.queries ? Object.keys(labConfig.queries) : [],
            note: `Use ${labConfig.server.targetName} for SIEM operations and log analysis.`,
          }, null, 2),
        },
      ],
    };
  },

  predefined_query: async (args: PredefinedQueryArgs, context: APIToolContext, queryConfig: NonNullable<LabConfig['queries']>[string]) => {
    const { params = {}, body = {} } = args;

    // Merge provided params/body with template
    const finalParams = { ...queryConfig.params, ...params };
    const finalBody = queryConfig.body ? { ...queryConfig.body, ...body } : body;

    try {
      // Use per-query auth if specified, otherwise fall back to default client
      let result;
      if (queryConfig.auth) {
        // Create temporary HTTP client with query-specific auth
        const queryAPIConfig = {
          baseUrl: '', // Not used since we have full URL
          auth: queryConfig.auth,
          verify_ssl: queryConfig.verify_ssl !== false
        };
        const queryClient = new HTTPClient(queryAPIConfig);
        result = await queryClient.makeRequest(queryConfig.url, queryConfig.method, {
          params: finalParams,
          body: finalBody,
          responseType: queryConfig.response_type || 'json',
        });
      } else {
        result = await context.httpClient.makeRequest(queryConfig.url, queryConfig.method, {
          params: finalParams,
          body: finalBody,
          responseType: queryConfig.response_type || 'json',
        });
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              query: queryConfig.description,
              endpoint: queryConfig.url,
              method: queryConfig.method,
              status: result.status,
              data: result.data,
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
              query: queryConfig.description,
              endpoint: queryConfig.url,
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },
};

/**
 * Generate API tool handlers with server-specific names
 */
export function generateAPIToolHandlers(
  serverConfig: LabConfig['server'], 
  queries?: LabConfig['queries'],
  includeGenericTools: boolean = true
): Record<string, APIToolHandler> {
  const handlers: Record<string, APIToolHandler> = {};
  
  // Map server-specific tool names to base handlers
  if (includeGenericTools) {
    handlers[`${serverConfig.toolPrefix}_api_call`] = baseAPIHandlers.api_call;
    handlers[`${serverConfig.toolPrefix}_api_info`] = baseAPIHandlers.api_info;
  }
  
  // Add predefined query handlers
  if (queries) {
    Object.entries(queries).forEach(([queryName, queryConfig]) => {
      handlers[`${serverConfig.toolPrefix}_${queryName}`] = async (args: any, context: APIToolContext) => {
        return baseAPIHandlers.predefined_query(args, context, queryConfig);
      };
    });
  }
  
  return handlers;
}