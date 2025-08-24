// SPDX-License-Identifier: BUSL-1.1

import { SSHConnectionManager } from '../ssh.js';
import { LabConfig, selectCredentials } from '../config.js';

export interface ToolContext {
  sshManager: SSHConnectionManager;
  labConfig: LabConfig;
}

export type ToolHandler = (args: any, context: ToolContext) => Promise<any>;

export const toolHandlers: Record<string, ToolHandler> = {
  kali_info: async (args: any, { labConfig }: ToolContext) => {
    if (!('enabled' in labConfig.instances.kali) || !labConfig.instances.kali.enabled) {
      return {
        content: [
          {
            type: 'text',
            text: 'Kali instance is not enabled in the current lab configuration.',
          },
        ],
      };
    }

    const kaliInstance = labConfig.instances.kali;
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            public_ip: kaliInstance.public_ip,
            private_ip: kaliInstance.private_ip,
            ssh_user: kaliInstance.ssh_user,
            instance_type: kaliInstance.instance_type,
            lab_name: labConfig.lab.name,
            vpc_cidr: labConfig.network.vpc_cidr,
          }, null, 2),
        },
      ],
    };
  },

  run_command: async (args: any, { sshManager, labConfig }: ToolContext) => {
    const { target, command, username = 'kali' } = args as {
      target: string;
      command: string;
      username?: string;
    };

    try {
      const credentials = selectCredentials(target, labConfig, username);

      const result = await sshManager.executeCommand(
        target,
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
              target,
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
              target,
              command,
              username,
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
      target,
      username = 'kali',
      type = 'interactive'
    } = args as {
      session_id?: string;
      target: string;
      username?: string;
      type?: 'interactive' | 'background';
    };

    try {
      const finalSessionId = session_id || `session_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const credentials = selectCredentials(target, labConfig, username);

      const session = await sshManager.createSession(
        finalSessionId,
        target,
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
              message: `Session '${sessionInfo.sessionId}' created successfully`
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

  list_sessions: async (args: any, { sshManager }: ToolContext) => {
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