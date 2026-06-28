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
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { type LabConfig } from './config.js';
import { SSHConnectionManager } from './ssh.js';
import { HTTPClient } from './http.js';
import { initTracing, shutdownTracing, traceToolCall } from './telemetry.js';
import { generateToolDefinitions } from './tools/definitions.js';
import { generateToolHandlers, type ToolHandler, type ToolContext } from './tools/handlers.js';
import { generateAPIToolDefinitions } from './tools/api-definitions.js';
import { generateAPIToolHandlers, type APIToolHandler, type APIToolContext } from './tools/api-handlers.js';
import {
  generateCompositeToolDefinitions,
  generateCompositeToolHandlers,
  compositeContextKinds,
  type CompositeTool,
  type CompositeHandler,
  type CompositeContext,
  type CompositeContextKind,
} from './tools/composites.js';

/**
 * Information passed to a `postToolHook` after a tool call resolves or rejects.
 */
export interface PostToolHookInfo {
  toolName: string;
  args: Record<string, unknown>;
  result?: unknown;
  durationMs: number;
  error?: Error;
}

/**
 * Hook fired after every MCP tool call. May return a Promise — async SIEM
 * transports (HTTP shipping, queued buffer flushes) are first-class. The
 * server awaits the returned promise inside its own try/catch, so a
 * rejected promise becomes a stderr diagnostic, not an unhandled rejection,
 * and the tool response is never disturbed (per ADR-027 best-effort
 * guarantee).
 */
export type PostToolHook = (info: PostToolHookInfo) => void | Promise<void>;

export interface CreateMCPServerOptions {
  postToolHook?: PostToolHook;
  /**
   * Maximum milliseconds to wait for an async `postToolHook` before the
   * tool response is returned anyway. Prevents a slow/hung SIEM transport
   * from blocking command execution (ADR-027 best-effort guarantee).
   * Defaults to 2000 ms; set to 0 to disable the timeout.
   */
  postToolHookTimeoutMs?: number;
  /**
   * Composite MCP tools (ORC-003 / ADR-045) this server opts into. A
   * composite is a single MCP tool that orchestrates several internal SSH/API
   * steps over the existing primitives. Domain composites live in the server
   * package and are registered here through the typed common seam; common
   * itself ships no domain composites.
   */
  composites?: CompositeTool[];
}

/**
 * Create and configure an MCP server with the provided lab configuration.
 *
 * `options.postToolHook` is fired once per tool call (success or error). It is
 * the extension point ADR-027 reserves for SIEM-event emission attached to MCP
 * command execution; common itself never imports red-team logic.
 */
const DEFAULT_HOOK_TIMEOUT_MS = 2000;

async function runHookWithTimeout(
  hook: PostToolHook,
  info: PostToolHookInfo,
  timeoutMs: number,
): Promise<void> {
  const ret = hook(info);
  if (!ret || typeof ret.then !== 'function') return;
  if (timeoutMs <= 0) {
    await ret;
    return;
  }
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<void>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`postToolHook timeout after ${timeoutMs}ms`)),
      timeoutMs,
    );
  });
  try {
    await Promise.race([ret, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

interface ServerClients {
  sshManager: SSHConnectionManager | null;
  httpClient: HTTPClient | null;
}

interface ToolRegistry {
  cachedTools: Tool[];
  cachedHandlers: Record<string, ToolHandler | APIToolHandler | CompositeHandler>;
  compositeKinds: Record<string, CompositeContextKind>;
}

interface ContextDeps {
  labConfig: LabConfig;
  clients: ServerClients;
  compositeKinds: Record<string, CompositeContextKind>;
}

interface CallToolDeps extends ContextDeps {
  cachedHandlers: Record<string, ToolHandler | APIToolHandler | CompositeHandler>;
  postToolHook?: PostToolHook;
  hookTimeoutMs: number;
}

/** Pre-generate tool definitions + handlers for every configured capability. */
function buildToolRegistry(
  labConfig: LabConfig,
  clients: ServerClients,
  composites: CompositeTool[],
): ToolRegistry {
  const cachedTools: Tool[] = [];
  const cachedHandlers: Record<string, ToolHandler | APIToolHandler | CompositeHandler> = {};
  let compositeKinds: Record<string, CompositeContextKind> = {};

  if (clients.sshManager) {
    cachedTools.push(...generateToolDefinitions(labConfig.server));
    Object.assign(cachedHandlers, generateToolHandlers(labConfig.server));
  }
  if (clients.httpClient) {
    // Only include generic tools if no predefined queries exist
    const includeGeneric = !labConfig.queries || Object.keys(labConfig.queries).length === 0;
    cachedTools.push(...generateAPIToolDefinitions(labConfig.server, labConfig.queries, includeGeneric));
    Object.assign(cachedHandlers, generateAPIToolHandlers(labConfig.server, labConfig.queries, includeGeneric));
  }
  // Composite tools (ORC-003 / ADR-045) register through the typed common seam.
  // Their context kind is tracked explicitly so dispatch routes SSH / HTTP
  // context by declaration, never by tool-name substring.
  if (composites.length > 0) {
    cachedTools.push(...generateCompositeToolDefinitions(labConfig.server, composites));
    Object.assign(cachedHandlers, generateCompositeToolHandlers(labConfig.server, composites));
    compositeKinds = compositeContextKinds(labConfig.server, composites);
  }

  return { cachedTools, cachedHandlers, compositeKinds };
}

/**
 * Build the composite context from the declared kind (ADR-045): routing is by
 * declaration, never by tool-name substrings. A declared client that is
 * unconfigured is a hard error before the handler runs.
 */
function buildCompositeContext(kind: CompositeContextKind, deps: ContextDeps): CompositeContext {
  const { labConfig, clients } = deps;
  const compositeContext: CompositeContext = { labConfig };
  if (kind === 'ssh' || kind === 'both') {
    if (!clients.sshManager) {
      throw new Error('Composite tool requires SSH but SSH manager not configured');
    }
    compositeContext.sshManager = clients.sshManager;
  }
  if (kind === 'api' || kind === 'both') {
    if (!clients.httpClient) {
      throw new Error('Composite tool requires API but HTTP client not configured');
    }
    compositeContext.httpClient = clients.httpClient;
  }
  return compositeContext;
}

/** Determine context type based on tool kind and available clients. */
function resolveToolContext(name: string, deps: ContextDeps): ToolContext | APIToolContext | CompositeContext {
  const { labConfig, clients, compositeKinds } = deps;
  const compositeKind = compositeKinds[name];
  if (compositeKind) {
    return buildCompositeContext(compositeKind, deps);
  }
  if (name.includes('_api_') || (labConfig.queries && Object.keys(labConfig.queries).some(q => name.endsWith(`_${q}`)))) {
    if (!clients.httpClient) {
      throw new Error('API tool requested but HTTP client not configured');
    }
    return { httpClient: clients.httpClient, labConfig };
  }
  if (!clients.sshManager) {
    throw new Error('SSH tool requested but SSH manager not configured');
  }
  return { sshManager: clients.sshManager, labConfig };
}

/** Build the CallTool request handler, including the best-effort post-tool hook. */
function makeCallToolHandler(deps: CallToolDeps) {
  return async (request: CallToolRequest) => {
    const { name, arguments: args } = request.params;

    const handler = deps.cachedHandlers[name];
    if (!handler) {
      throw new Error(`Unknown tool: ${name}`);
    }

    const context = resolveToolContext(name, deps);
    const safeArgs: Record<string, unknown> = args ?? {};
    const t0 = Date.now();
    try {
      const result = await traceToolCall<{ content: { type: string; text: string }[] }>(
        name,
        deps.labConfig.server.name,
        safeArgs,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- handler union narrowed by resolveToolContext
        () => (handler as any)(safeArgs, context),
      );
      if (deps.postToolHook) {
        // Fire-and-forget: telemetry must NEVER add latency to the tool
        // response. Errors and timeouts are logged to stderr so a bad hook is
        // observable without blocking. The hook timeout still applies to the
        // lifetime of the in-flight task — we don't await it on the response path.
        void runHookWithTimeout(
          deps.postToolHook,
          { toolName: name, args: safeArgs, result, durationMs: Date.now() - t0 },
          deps.hookTimeoutMs,
        ).catch((hookErr) => {
          console.error('[MCP] postToolHook error:', hookErr);
        });
      }
      return result;
    } catch (err) {
      if (deps.postToolHook) {
        const error = err instanceof Error ? err : new Error(String(err));
        void runHookWithTimeout(
          deps.postToolHook,
          { toolName: name, args: safeArgs, durationMs: Date.now() - t0, error },
          deps.hookTimeoutMs,
        ).catch((hookErr) => {
          console.error('[MCP] postToolHook error:', hookErr);
        });
      }
      throw err;
    }
  };
}

export function createMCPServer(labConfig: LabConfig, options: CreateMCPServerOptions = {}) {
  const { postToolHook } = options;
  const hookTimeoutMs = options.postToolHookTimeoutMs ?? DEFAULT_HOOK_TIMEOUT_MS;
  // Initialize clients and OTel tracing based on config
  const clients: ServerClients = {
    sshManager: labConfig.containers ? new SSHConnectionManager() : null,
    httpClient: labConfig.api ? new HTTPClient(labConfig.api) : null,
  };
  const { sshManager } = clients;
  initTracing(labConfig.server.name);

  const { cachedTools, cachedHandlers, compositeKinds } = buildToolRegistry(
    labConfig,
    clients,
    options.composites ?? [],
  );

  console.error(`[MCP] Initialized ${labConfig.server.name} with lab: ${labConfig.lab.name}`);
  console.error(`[MCP] Available capabilities: ${clients.sshManager ? 'SSH' : ''}${clients.sshManager && clients.httpClient ? ' + ' : ''}${clients.httpClient ? 'HTTP API' : ''}`);

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

  server.setRequestHandler(
    CallToolRequestSchema,
    makeCallToolHandler({ labConfig, clients, compositeKinds, cachedHandlers, postToolHook, hookTimeoutMs }),
  );

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
        const gracefulShutdown = async (signal: string): Promise<void> => {
          console.error(`[MCP] Shutting down gracefully (${signal})...`);
          await shutdownTracing();
          if (sshManager) {
            // disconnectAll now propagates SSHError on teardown contract
            // failures so callers can detect unclean shutdown. The signal
            // handler still needs to exit; log the failure non-zero rather
            // than letting an unhandled rejection terminate Node abruptly.
            try {
              await sshManager.disconnectAll();
            } catch (err) {
              console.error('[MCP] disconnectAll failed during shutdown:', err);
              process.exit(1);
              return;
            }
          }
          process.exit(0);
        };

        process.on('SIGINT', () => { void gracefulShutdown('SIGINT'); });
        process.on('SIGTERM', () => { void gracefulShutdown('SIGTERM'); });

        handlersSetup = true;
      }
    }
  };
}
