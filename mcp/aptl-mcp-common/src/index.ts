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
  CommandRequest
} from './ssh.js';
export { expandTilde } from './utils.js';

// Export MCP server creation and types
export { createMCPServer } from './server.js';
export type { LabConfig } from './config.js';
export { loadLabConfig, substituteEnvVars, parseDotEnv } from './config.js';
export type { ToolContext } from './tools/handlers.js';

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
 */
export async function startServer(callerMetaUrl: string): Promise<void> {
  const { createMCPServer } = await import('./server.js');
  const { loadLabConfig } = await import('./config.js');

  const configPath = resolve(new URL('.', callerMetaUrl).pathname, '..', 'docker-lab-config.json');
  const config = await loadLabConfig(configPath);
  const server = createMCPServer(config);
  await server.start();
}