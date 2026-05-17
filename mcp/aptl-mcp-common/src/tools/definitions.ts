

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { LabConfig } from '../config.js';

/**
 * Canonical `session_id` validation schema, shared across every tool
 * argument that accepts one (OBS-003 / ADR-033 / codex pre-push cycle
 * 3 finding-4 + finding-10). Matches the Python `_ID_RE` in
 * `src/aptl/core/runstore.py`, the TS `ID_RE` in
 * `mcp/aptl-mcp-common/src/runs.ts`, and the shell `valid_id()` in
 * `containers/kali/scripts/aptl-wrap-shell.sh`. Enforcing the
 * contract at MCP ingress means downstream layers (PTY tee, Kali
 * wrapper, harvest) all see the same id — no more split-brain where
 * each layer applies its own fallback substitution and captures end
 * up under different paths.
 *
 * - `^[A-Za-z0-9_][A-Za-z0-9._-]*$` — letters, digits, `_`, `.`, `-`,
 *   leading char alphanumeric or `_` (so the `_unbound` sentinel and
 *   `_invalid` fallback round-trip).
 * - `..` is explicitly forbidden at the handler precondition layer
 *   (JSON Schema cannot express "no `..` substring" alone, so the
 *   handler asserts it).
 * - Length capped at 128 to keep filesystem paths bounded.
 */
const SESSION_ID_SCHEMA = {
  type: 'string' as const,
  pattern: '^[A-Za-z0-9_][A-Za-z0-9._-]*$',
  maxLength: 128,
};

export function generateToolDefinitions(serverConfig: LabConfig['server']): Tool[] {
  return [
  {
    name: `${serverConfig.toolPrefix}_info`,
    description: `Get information about the ${serverConfig.targetName} instance in the lab`,
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: `${serverConfig.toolPrefix}_run_command`,
    description: `Execute a command on the ${serverConfig.targetName} instance (creates temporary session)`,
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: `Command to execute on ${serverConfig.targetName}`,
        },
      },
      required: ['command'],
    },
  },
  {
    name: `${serverConfig.toolPrefix}_interactive_session`,
    description: 'Create a persistent session that waits for each command to complete with structured output',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          ...SESSION_ID_SCHEMA,
          description: 'Unique session identifier (optional, auto-generated if not provided)',
        },
        timeout_ms: {
          type: 'number',
          description: 'Session timeout in milliseconds before automatic closure (default: 600000 = 10 minutes)',
          default: 600000,
        },
      },
      required: [],
    },
  },
  {
    name: `${serverConfig.toolPrefix}_background_session`,
    description: 'Create a background session for long-running processes or interactive programs',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          ...SESSION_ID_SCHEMA,
          description: 'Unique session identifier (optional, auto-generated if not provided)',
        },
        raw: {
          type: 'boolean',
          description: 'Use raw mode for interactive programs (msfconsole, scanmem, gdb) that need clean stdin/stdout',
          default: false,
        },
        timeout_ms: {
          type: 'number',
          description: 'Session timeout in milliseconds before automatic closure (default: 600000 = 10 minutes)',
          default: 600000,
        },
      },
      required: [],
    },
  },
  {
    name: `${serverConfig.toolPrefix}_session_command`,
    description: 'Execute a command in an existing persistent session',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          ...SESSION_ID_SCHEMA,
          description: 'Session identifier to execute command in',
        },
        command: {
          type: 'string',
          description: 'Command to execute',
        },
        timeout: {
          type: 'number',
          description: 'Command timeout in milliseconds (default: 30000)',
          default: 30000,
        },
        raw: {
          type: 'boolean',
          description: 'Execute in raw mode (no echo wrapping, for interactive programs). Defaults to session mode',
          default: false,
        },
      },
      required: ['session_id', 'command'],
    },
  },
  {
    name: `${serverConfig.toolPrefix}_list_sessions`,
    description: 'List all active persistent sessions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: `${serverConfig.toolPrefix}_close_session`,
    description: 'Close a specific persistent session',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          ...SESSION_ID_SCHEMA,
          description: 'Session identifier to close',
        },
      },
      required: ['session_id'],
    },
  },
  {
    name: `${serverConfig.toolPrefix}_get_session_output`,
    description: 'Get buffered output from a background session',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          ...SESSION_ID_SCHEMA,
          description: 'Session identifier to get output from',
        },
        lines: {
          type: 'number',
          description: 'Number of recent lines to retrieve (optional, default: all)',
        },
        clear: {
          type: 'boolean',
          description: 'Clear buffer after reading (default: false)',
          default: false,
        },
      },
      required: ['session_id'],
    },
  },
  {
    name: `${serverConfig.toolPrefix}_close_all_sessions`,
    description: 'Close all active persistent sessions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  ];
}
