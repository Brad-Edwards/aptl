

import { SSHConnectionManager, SessionMetadata } from 'aptl-mcp-common';
import { LabConfig, getMinetestClientCredentials } from '../config.js';

export interface ToolContext {
  sshManager: SSHConnectionManager;
  labConfig: LabConfig;
}

export type ToolHandler = (args: any, context: ToolContext) => Promise<any>;

export const toolHandlers: Record<string, ToolHandler> = {
  minetest_client_info: async (args: any, { labConfig }: ToolContext) => {
    if (!labConfig.minetestClient.enabled) {
      return {
        content: [
          {
            type: 'text',
            text: 'Minetest Client instance is not enabled in the current lab configuration.',
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            minetest_client_ip: labConfig.minetestClient.public_ip,
            ssh_user: labConfig.minetestClient.ssh_user,
            ssh_port: labConfig.minetestClient.ssh_port,
            lab_name: labConfig.lab.name,
            lab_network: labConfig.network.vpc_cidr,
            note: 'Use Minetest Client for memory scanning operations. Target Minetest processes in this container.',
          }, null, 2),
        },
      ],
    };
  },

  mc_client_run_command: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { command } = args as {
      command: string;
    };

    try {
      const credentials = getMinetestClientCredentials(labConfig);

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

  mc_client_interactive_session: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { 
      session_id,
      timeout_ms = 600000
    } = args as {
      session_id?: string;
      timeout_ms?: number;
    };

    try {
      const finalSessionId = session_id || `session_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const credentials = getMinetestClientCredentials(labConfig);

      const session = await sshManager.createSession(
        finalSessionId,
        credentials.target,
        credentials.username,
        'interactive',
        credentials.sshKey,
        credentials.port,
        'normal',
        timeout_ms
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
              type: 'interactive',
              mode: 'normal',
              created_at: sessionInfo.createdAt,
              message: `Minetest Client session '${sessionInfo.sessionId}' created successfully`
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

  mc_client_background_session: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { 
      session_id,
      raw = false,
      timeout_ms = 600000
    } = args as {
      session_id?: string;
      raw?: boolean;
      timeout_ms?: number;
    };

    try {
      const finalSessionId = session_id || `bg_session_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const credentials = getMinetestClientCredentials(labConfig);

      const session = await sshManager.createSession(
        finalSessionId,
        credentials.target,
        credentials.username,
        'background',
        credentials.sshKey,
        credentials.port,
        raw ? 'raw' : 'normal',
        timeout_ms
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
              type: 'background',
              mode: raw ? 'raw' : 'normal',
              created_at: sessionInfo.createdAt,
              message: `Minetest Client background session '${sessionInfo.sessionId}' created successfully${raw ? ' (raw mode for interactive programs)' : ''}`
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

  mc_client_session_command: async (args: any, { sshManager }: ToolContext) => {
    const { session_id, command, timeout = 30000, raw } = args as {
      session_id: string;
      command: string;
      timeout?: number;
      raw?: boolean;
    };

    try {
      const result = await sshManager.executeInSession(session_id, command, timeout, raw);

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

  mc_client_list_sessions: async (_args: any, { sshManager }: ToolContext) => {
    try {
      const sessions = sshManager.listSessions();

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              sessions: sessions.map((session: SessionMetadata) => ({
                session_id: session.sessionId,
                target: session.target,
                username: session.username,
                type: session.type,
                mode: session.mode,
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

  mc_client_close_session: async (args: any, { sshManager }: ToolContext) => {
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

  mc_client_get_session_output: async (args: any, { sshManager }: ToolContext) => {
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

  mc_client_close_all_sessions: async (_args: any, { sshManager }: ToolContext) => {
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