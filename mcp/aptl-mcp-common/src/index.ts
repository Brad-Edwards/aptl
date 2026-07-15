import { resolve } from 'path';

// Export the working SSH implementation exactly as-is
export {
  SSHConnectionManager,
  PersistentSession,
  SSHError,
  CommandResult,
  SessionType,
  SessionMode,
  SessionMetadata,
  CommandRequest,
  SessionConnectOptions
} from './ssh.js';
export { expandTilde } from './utils.js';

// Export MCP server creation and types
export { createMCPServer } from './server.js';
export type { CreateMCPServerOptions, PostToolHook, PostToolHookInfo } from './server.js';
export { initTracing, shutdownTracing, getTracer, traceToolCall } from './telemetry.js';
export {
  redact,
  REDACTED,
  redactShortPasswordFlag,
  redactBasicAuthUser,
  redactNtlmHashFlag,
  redactLdapPasswordFlag,
  experimentNoRedactActive,
} from './redaction.js';
export type { LabConfig } from './config.js';
export { loadLabConfig, substituteEnvVars, parseDotEnv } from './config.js';
export type { ToolContext } from './tools/handlers.js';
export {
  loadActiveTraceId,
  resolveActiveRunDir,
  mcpSideDir,
  kaliSideSessionDir,
  mcpSessionJsonl,
  createPtyTeeWriter,
} from './runs.js';
export type { PtyChunkDirection, PtyTeeRecord } from './runs.js';
export { harvestSession } from './captures.js';
export type { HarvestOptions } from './captures.js';

// Export HTTP/API functionality
export { HTTPClient, type HTTPResponse, type HTTPError } from './http.js';
export { generateAPIToolDefinitions } from './tools/api-definitions.js';
export { generateAPIToolHandlers, type APIToolContext } from './tools/api-handlers.js';

/**
 * Standard entry point for all APTL MCP servers.
 * Loads docker-lab-config.json relative to the calling module's directory.
 *
 * @param callerMetaUrl - Pass `import.meta.url` from the calling index.ts
 *                        so the config file is resolved relative to the server package,
 *                        not relative to aptl-mcp-common.
 * @param options - Optional `createMCPServer` options (e.g. `postToolHook`).
 */
export async function startServer(
  callerMetaUrl: string,
  options?: import('./server.js').CreateMCPServerOptions,
): Promise<void> {
  const { createMCPServer } = await import('./server.js');
  const { loadLabConfig } = await import('./config.js');

  const configPath = resolve(new URL('.', callerMetaUrl).pathname, '..', 'docker-lab-config.json');
  const config = await loadLabConfig(configPath);
  const server = createMCPServer(config, options);
  await server.start();
}
