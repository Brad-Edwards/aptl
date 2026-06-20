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

type QueryConfig = NonNullable<LabConfig['queries']>[string];

// Resolve the effective request body for a predefined query. A string passes
// through as a raw payload (e.g. XML for Wazuh rule uploads); undefined/null
// falls back to the template body; otherwise the provided body is merged over
// the template object.
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- body is untyped (MCP SDK args); behavior must match the prior `any` flow
function resolveQueryBody(body: unknown, queryConfig: QueryConfig): any {
  if (typeof body === 'string') {
    return body;
  }
  if (body === undefined || body === null) {
    return queryConfig.body;
  }
  return queryConfig.body ? { ...queryConfig.body, ...(body as Record<string, unknown>) } : body;
}

// Substitute `{key}` path parameters into the query URL and collect the
// remaining params as query-string params.
function buildQueryUrl(
  queryConfig: QueryConfig,
  finalParams: Record<string, unknown>,
): { url: string; queryParams: Record<string, unknown> } {
  let url = queryConfig.url;
  const queryParams: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(finalParams)) {
    const placeholder = `{${key}}`;
    if (url.includes(placeholder)) {
      url = url.replace(placeholder, encodeURIComponent(String(value)));
    } else {
      queryParams[key] = value;
    }
  }
  return { url, queryParams };
}

// Execute a predefined query, using per-query auth when specified (via a
// temporary HTTP client) otherwise the default client.
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- finalBody is untyped (MCP SDK args); behavior must match the prior `any` flow
function runPredefinedQuery(
  queryConfig: QueryConfig,
  context: APIToolContext,
  url: string,
  queryParams: Record<string, unknown>,
  finalBody: any,
) {
  if (queryConfig.auth) {
    // Create temporary HTTP client with query-specific auth.
    // SEC-006 / ADR-034 § Gotchas: both `verify_ssl` and
    // `ca_cert_path` must inherit from the top-level api config
    // when the query does not override them. Treating
    // `queryConfig.verify_ssl !== false` as the verify decision
    // forced verification on whenever a query had its own auth
    // block but no explicit `verify_ssl`, which silently broke the
    // documented local-debug override at the api level and made
    // every predefined query repeat the flag. Explicit query
    // override first, then fall back to the api setting.
    const queryAPIConfig = {
      baseUrl: '', // Not used since we have full URL
      auth: queryConfig.auth,
      verify_ssl: queryConfig.verify_ssl ?? context.labConfig.api?.verify_ssl ?? true,
      ca_cert_path: queryConfig.ca_cert_path ?? context.labConfig.api?.ca_cert_path,
    };
    const queryClient = new HTTPClient(queryAPIConfig);
    return queryClient.makeRequest(url, queryConfig.method, {
      params: queryParams,
      body: finalBody,
      responseType: queryConfig.response_type || 'json',
    });
  }
  return context.httpClient.makeRequest(url, queryConfig.method, {
    params: queryParams,
    body: finalBody,
    responseType: queryConfig.response_type || 'json',
  });
}

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
    const { params = {}, body } = args as any;

    // Merge provided params with template
    const finalParams = { ...queryConfig.params, ...params };
    const finalBody = resolveQueryBody(body, queryConfig);
    const { url, queryParams } = buildQueryUrl(queryConfig, finalParams);

    try {
      const result = await runPredefinedQuery(queryConfig, context, url, queryParams, finalBody);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              query: queryConfig.description,
              endpoint: url,
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
