

import { Tool } from '@modelcontextprotocol/sdk/types.js';

export const toolDefinitions: Tool[] = [
  {
    name: 'kali_info',
    description: 'Get information about the Kali Linux instance in the lab',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'run_command',
    description: 'Execute a command on the Kali instance (creates temporary session)',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'Command to execute on Kali',
        },
      },
      required: ['command'],
    },
  },
  {
    name: 'create_session',
    description: 'Create a persistent session that waits for each command to complete with structured output',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
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
    name: 'create_background_session',
    description: 'Create a background session for long-running processes or interactive programs',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
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
    name: 'session_command',
    description: 'Execute a command in an existing persistent session',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
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
    name: 'list_sessions',
    description: 'List all active persistent sessions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'close_session',
    description: 'Close a specific persistent session',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
          description: 'Session identifier to close',
        },
      },
      required: ['session_id'],
    },
  },
  {
    name: 'get_session_output',
    description: 'Get buffered output from a background session',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
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
    name: 'close_all_sessions',
    description: 'Close all active persistent sessions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];