

import { Tool } from '@modelcontextprotocol/sdk/types.js';

export const toolDefinitions: Tool[] = [
  {
    name: 'container_info',
    description: 'Get information about the Minetest server container in the lab',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'mc_server_run_command',
    description: 'Execute a command on the Minetest server container (creates temporary session)',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'Command to execute on Minetest server container',
        },
      },
      required: ['command'],
    },
  },
  {
    name: 'mc_server_create_session',
    description: 'Create a new persistent SSH session on Minetest server container',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: {
          type: 'string',
          description: 'Unique session identifier (optional, auto-generated if not provided)',
        },
        type: {
          type: 'string',
          enum: ['interactive', 'background'],
          description: 'Session type: interactive for stateful operations, background for long-running processes',
          default: 'interactive',
        },
      },
      required: [],
    },
  },
  {
    name: 'mc_server_session_command',
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
      },
      required: ['session_id', 'command'],
    },
  },
  {
    name: 'mc_server_list_sessions',
    description: 'List all active persistent sessions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'mc_server_close_session',
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
    name: 'mc_server_get_session_output',
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
    name: 'mc_server_close_all_sessions',
    description: 'Close all active persistent sessions',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];