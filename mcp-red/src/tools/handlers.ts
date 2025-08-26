

import { SSHConnectionManager } from '../ssh.js';
import { LabConfig, getKaliCredentials } from '../config.js';

/**
 * Context provided to all tool handlers.
 */
export interface ToolContext {
  /** SSH connection manager for executing commands */
  sshManager: SSHConnectionManager;
  /** Lab configuration with network and instance details */
  labConfig: LabConfig;
}

/**
 * Tool handler function signature.
 * 
 * @param args - Tool-specific arguments from MCP request
 * @param context - Shared context with SSH manager and config
 * @returns Tool execution result in MCP response format
 */
export type ToolHandler = (args: any, context: ToolContext) => Promise<any>;

/**
 * Tool handlers for MCP operations.
 * Each handler processes specific tool requests from AI agents.
 * 
 * Available tools:
 * - kali_info: Get Kali instance information
 * - run_command: Execute single command on Kali
 * - create_session: Create persistent SSH session
 * - session_command: Execute command in existing session
 * - list_sessions: List all active sessions
 * - close_session: Close specific session
 * - get_session_output: Get buffered output from background session
 * - close_all_sessions: Cleanup all active sessions
 */
export const toolHandlers: Record<string, ToolHandler> = {
  kali_info: async (args: any, { labConfig }: ToolContext) => {
    if (!labConfig.kali.enabled) {
      return {
        content: [
          {
            type: 'text',
            text: 'Kali instance is not enabled in the current lab configuration.',
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            kali_ip: labConfig.kali.public_ip,
            ssh_user: labConfig.kali.ssh_user,
            ssh_port: labConfig.kali.ssh_port,
            lab_name: labConfig.lab.name,
            lab_network: labConfig.network.vpc_cidr,
            note: 'Use Kali for red team operations. Enumerate and attack victim targets in lab network. DO NOT attack SIEM infrastructure.',
          }, null, 2),
        },
      ],
    };
  },

  run_command: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { command } = args as {
      command: string;
    };

    try {
      const credentials = getKaliCredentials(labConfig);

      const result = await sshManager.executeCommand(
        credentials.target,
        credentials.username,
        credentials.sshKey,
        command,
        credentials.port
      );

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              target: credentials.target,
              command,
              username: credentials.username,
              success: true,
              output: result,
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
              command,
              success: false,
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },

  create_session: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { 
      session_id,
      type = 'interactive'
    } = args as {
      session_id?: string;
      type?: 'interactive' | 'background';
    };

    try {
      const finalSessionId = session_id || `session_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const credentials = getKaliCredentials(labConfig);

      const session = await sshManager.createSession(
        finalSessionId,
        credentials.target,
        credentials.username,
        type,
        credentials.sshKey,
        credentials.port
      );

      const sessionInfo = session.getSessionInfo();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              session_id: sessionInfo.sessionId,
              target: sessionInfo.target,
              username: sessionInfo.username,
              type: sessionInfo.type,
              created_at: sessionInfo.createdAt,
              message: `Kali session '${sessionInfo.sessionId}' created successfully`
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
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },

  session_command: async (args: any, { sshManager }: ToolContext) => {
    const { session_id, command, timeout = 30000 } = args as {
      session_id: string;
      command: string;
      timeout?: number;
    };

    try {
      const result = await sshManager.executeInSession(session_id, command, timeout);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              session_id,
              command,
              output: result.stdout,
              stderr: result.stderr,
              exit_code: result.code,
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
              session_id,
              command,
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },

  list_sessions: async (_args: any, { sshManager }: ToolContext) => {
    try {
      const sessions = sshManager.listSessions();

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              sessions: sessions.map(session => ({
                session_id: session.sessionId,
                target: session.target,
                username: session.username,
                type: session.type,
                created_at: session.createdAt,
                last_activity: session.lastActivity,
                is_active: session.isActive,
                command_count: session.commandHistory.length
              })),
              total_sessions: sessions.length
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
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },

  close_session: async (args: any, { sshManager }: ToolContext) => {
    const { session_id } = args as { session_id: string };

    try {
      const closed = await sshManager.closeSession(session_id);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: closed,
              session_id,
              message: closed ? `Session '${session_id}' closed successfully` : `Session '${session_id}' not found`
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
              session_id,
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },

  get_session_output: async (args: any, { sshManager }: ToolContext) => {
    const { session_id, lines, clear = false } = args as {
      session_id: string;
      lines?: number;
      clear?: boolean;
    };

    try {
      // Add validation to ensure session exists and is active
      const session = sshManager.getSession(session_id);
      if (!session) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                session_id,
                error: `Session '${session_id}' not found`
              }, null, 2),
            },
          ],
        };
      }

      const output = session.getBufferedOutput(lines, clear);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              session_id,
              output: output.join(''),
              lines_returned: output.length,
              buffer_cleared: clear
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
              session_id,
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },

  close_all_sessions: async (_args: any, { sshManager }: ToolContext) => {
    try {
      const sessions = sshManager.listSessions();
      const sessionCount = sessions.length;
      
      await sshManager.disconnectAll();

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              sessions_closed: sessionCount,
              message: `All ${sessionCount} sessions have been closed`
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
              error: error instanceof Error ? error.message : 'Unknown error',
            }, null, 2),
          },
        ],
      };
    }
  },
};