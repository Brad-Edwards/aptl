

import { SSHConnectionManager } from '../ssh.js';
import { LabConfig } from '../config.js';

export interface ToolContext {
  sshManager: SSHConnectionManager;
  labConfig: LabConfig;
}

export type ToolHandler = (args: any, context: ToolContext) => Promise<any>;

export const toolHandlers: Record<string, ToolHandler> = {
  container_info: async (args: any, { labConfig }: ToolContext) => {
    const minestContainer = labConfig.containers?.['minetest-server'];
    if (!minestContainer?.enabled) {
      return {
        content: [
          {
            type: 'text',
            text: 'Minetest server container is not enabled in the current lab configuration.',
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            container_name: minestContainer.container_name,
            container_ip: minestContainer.container_ip,
            ssh_user: minestContainer.ssh_user,
            ssh_port: minestContainer.ssh_port || 22,
            lab_name: labConfig.lab.name,
            lab_network: labConfig.lab.network_subnet,
            note: 'Minetest server container for GameConqueror memory scanning demo. Target for red team operations.',
          }, null, 2),
        },
      ],
    };
  },

  mc_server_run_command: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { command } = args as {
      command: string;
    };

    try {
      const minestContainer = labConfig.containers?.['minetest-server'];
      if (!minestContainer?.enabled) {
        throw new Error('Minetest server container is not enabled');
      }

      console.error(`[DEBUG] Connecting to: ${minestContainer.container_ip}:${minestContainer.ssh_port || 22} as ${minestContainer.ssh_user}`);
      console.error(`[DEBUG] Available containers:`, Object.keys(labConfig.containers || {}));

      const result = await sshManager.executeCommand(
        minestContainer.container_ip,
        minestContainer.ssh_user,
        minestContainer.ssh_key,
        command,
        minestContainer.ssh_port || 22
      );

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              target: minestContainer.container_ip,
              command,
              username: minestContainer.ssh_user,
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

  mc_server_create_session: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { 
      session_id,
      type = 'interactive'
    } = args as {
      session_id?: string;
      type?: 'interactive' | 'background';
    };

    try {
      const finalSessionId = session_id || `session_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const minestContainer = labConfig.containers?.['minetest-server'];
      if (!minestContainer?.enabled) {
        throw new Error('Minetest server container is not enabled');
      }

      const session = await sshManager.createSession(
        finalSessionId,
        minestContainer.container_ip,
        minestContainer.ssh_user,
        type,
        minestContainer.ssh_key,
        minestContainer.ssh_port || 22
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
              message: `Minetest server session '${sessionInfo.sessionId}' created successfully`
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

  mc_server_session_command: async (args: any, { sshManager }: ToolContext) => {
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

  mc_server_list_sessions: async (_args: any, { sshManager }: ToolContext) => {
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

  mc_server_close_session: async (args: any, { sshManager }: ToolContext) => {
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

  mc_server_get_session_output: async (args: any, { sshManager }: ToolContext) => {
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

  mc_server_close_all_sessions: async (_args: any, { sshManager }: ToolContext) => {
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