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
  if (!ret || typeof (ret as Promise<void>).then !== 'function') return;
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

export function createMCPServer(labConfig: LabConfig, options: CreateMCPServerOptions = {}) {
  const { postToolHook } = options;
  const hookTimeoutMs = options.postToolHookTimeoutMs ?? DEFAULT_HOOK_TIMEOUT_MS;
  // Initialize clients and OTel tracing based on config
  const sshManager = labConfig.containers ? new SSHConnectionManager() : null;
  const httpClient = labConfig.api ? new HTTPClient(labConfig.api) : null;
  initTracing(labConfig.server.name);

  // Pre-generate tools and handlers based on available capabilities
  let cachedTools: Tool[] = [];
  let cachedHandlers: Record<string, ToolHandler | APIToolHandler> = {};

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

    const safeArgs: Record<string, unknown> = (args ?? {}) as Record<string, unknown>;
    const t0 = Date.now();
    try {
      // Context is narrowed to the correct type above based on tool name
      const result = await traceToolCall<{ content: { type: string; text: string }[] }>(
        name,
        labConfig.server.name,
        safeArgs,
        () => (handler as any)(safeArgs, context),
      );
      if (postToolHook) {
        // Fire-and-forget: telemetry must NEVER add latency to the tool
        // response. Errors and timeouts are logged to stderr so a bad
        // hook is observable without blocking. The hook timeout still
        // applies to the lifetime of the in-flight task — we don't
        // await it on the response path.
        void runHookWithTimeout(
          postToolHook,
          { toolName: name, args: safeArgs, result, durationMs: Date.now() - t0 },
          hookTimeoutMs,
        ).catch((hookErr) => {
          console.error('[MCP] postToolHook error:', hookErr);
        });
      }
      return result;
    } catch (err) {
      if (postToolHook) {
        const error = err instanceof Error ? err : new Error(String(err));
        void runHookWithTimeout(
          postToolHook,
          { toolName: name, args: safeArgs, durationMs: Date.now() - t0, error },
          hookTimeoutMs,
        ).catch((hookErr) => {
          console.error('[MCP] postToolHook error:', hookErr);
        });
      }
      throw err;
    }
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
          await shutdownTracing();
          if (sshManager) {
            await sshManager.disconnectAll();
          }
          process.exit(0);
        });

        process.on('SIGTERM', async () => {
          console.error('[MCP] Shutting down gracefully...');
          await shutdownTracing();
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
