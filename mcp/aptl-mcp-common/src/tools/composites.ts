/**
 * Composite MCP tool registration seam (ORC-003 / ADR-045).
 *
 * A composite tool exposes a single MCP tool name and a compact result, but
 * its internal steps reuse the same canonical primitives a manually
 * orchestrating agent would have used (SSH via `SSHConnectionManager`, API via
 * `HTTPClient`). This module is ONLY the typed registration seam: it produces
 * the MCP tool definitions, the handler map, and the per-tool context-kind map
 * that `createMCPServer` consumes. It contains no domain logic and no
 * server-specific (red/blue) behaviour — domain composites live in their own
 * server package and are passed in via `CreateMCPServerOptions.composites`.
 *
 * Per ADR-045 the server routes composite context by the declared
 * `contextKind`, NOT by tool-name substrings, so composites that are neither
 * plain SSH tools nor predefined API queries dispatch unambiguously.
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { LabConfig } from '../config.js';
import { SSHConnectionManager } from '../ssh.js';
import { HTTPClient } from '../http.js';

/** Which lab clients a composite handler needs at dispatch time. */
export type CompositeContextKind = 'ssh' | 'api' | 'both';

/**
 * Context handed to a composite handler. `sshManager` / `httpClient` are
 * populated according to the composite's declared `contextKind`; the server
 * throws before invoking the handler if a declared client is unconfigured, so
 * a handler that declared `ssh` can rely on `sshManager` being present.
 */
export interface CompositeContext {
  labConfig: LabConfig;
  sshManager?: SSHConnectionManager;
  httpClient?: HTTPClient;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- MCP SDK provides untyped args; validated by the composite's JSON Schema before dispatch
export type CompositeHandler = (args: any, context: CompositeContext) => Promise<{ content: { type: string; text: string }[] }>;

/**
 * One internal step a composite executed, surfaced in the composite's result
 * envelope so command-bearing steps stay visible to the red capture / OCSF
 * path (ADR-045). A composite must not make its internal shell commands
 * disappear from `ocsf.jsonl` / `tool-calls.jsonl` merely because the agent
 * made one top-level tool call.
 */
export interface CompositeStepRecord {
  command: string;
  exit_code?: number;
  signal?: string;
  success?: boolean;
  session_id?: string;
  duration_ms?: number;
}

/**
 * A typed composite registration entry (ADR-045 extensibility seam). Adding a
 * new composite is one of these plus an opt-in via `options.composites`; the
 * server factory's core dispatch never changes.
 */
export interface CompositeTool {
  /** Unprefixed tool-name suffix; the seam prefixes it with `toolPrefix`. */
  name: string;
  description: string;
  /** JSON Schema for the composite's MCP ingress; typed and bounded inputs only. */
  inputSchema: Tool['inputSchema'];
  contextKind: CompositeContextKind;
  handler: CompositeHandler;
}

function prefixedName(serverConfig: LabConfig['server'], composite: CompositeTool): string {
  return `${serverConfig.toolPrefix}_${composite.name}`;
}

/** Build the MCP `Tool[]` definitions for a server's composites. */
export function generateCompositeToolDefinitions(
  serverConfig: LabConfig['server'],
  composites: CompositeTool[],
): Tool[] {
  return composites.map((composite) => ({
    name: prefixedName(serverConfig, composite),
    description: composite.description,
    inputSchema: composite.inputSchema,
  }));
}

/** Build the prefixed-name → handler map for a server's composites. */
export function generateCompositeToolHandlers(
  serverConfig: LabConfig['server'],
  composites: CompositeTool[],
): Record<string, CompositeHandler> {
  const handlers: Record<string, CompositeHandler> = {};
  for (const composite of composites) {
    handlers[prefixedName(serverConfig, composite)] = composite.handler;
  }
  return handlers;
}

/**
 * Build the prefixed-name → context-kind map the server uses to route
 * composite context explicitly (ADR-045: not by tool-name substring).
 */
export function compositeContextKinds(
  serverConfig: LabConfig['server'],
  composites: CompositeTool[],
): Record<string, CompositeContextKind> {
  const kinds: Record<string, CompositeContextKind> = {};
  for (const composite of composites) {
    kinds[prefixedName(serverConfig, composite)] = composite.contextKind;
  }
  return kinds;
}
