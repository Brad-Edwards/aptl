

import { SSHConnectionManager, SessionMetadata, SSHError } from '../ssh.js';
import { LabConfig, getTargetCredentials } from '../config.js';
import { ShellType } from '../shells.js';
import { harvestSession } from '../captures.js';

/**
 * Reject session ids whose JSON-schema pattern admits them but which
 * still contain the `..` path-traversal token (the schema regex
 * tolerates `.` but cannot exclude the `..` substring). Called at
 * the top of every handler that accepts a session_id arg so the
 * canonical contract is enforced at MCP ingress rather than via
 * each downstream layer's fallback substitution (codex pre-push
 * cycle 3 finding-4).
 */
function assertSessionIdContract(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new SSHError(`invalid session_id: must be a non-empty string`);
  }
  if (value.includes('..')) {
    throw new SSHError(`invalid session_id (contains '..'): ${JSON.stringify(value)}`);
  }
}

/**
 * OBS-003 / ADR-033: resolve the docker container name that backs
 * the SSH target for this MCP server, so the close_session /
 * close_all_sessions handlers can harvest per-session captures out
 * of the `kali_captures` (or analogous) named volume into
 * `.aptl/runs/<run_id>/kali-side/<session_id>/` on the host.
 *
 * Returns `undefined` when the lab is configured for an API-only
 * target (no container) or when the configKey is missing — those
 * MCP servers don't ship captures and harvest is a no-op.
 */
function resolveCaptureContainer(labConfig: LabConfig): string | undefined {
  const key = labConfig.server.configKey;
  if (!key || !labConfig.containers) return undefined;
  return labConfig.containers[key]?.container_name;
}

/**
 * Run capture harvest for the named session, best-effort. Returns
 * `true` when harvest completed cleanly (or there was nothing to
 * harvest because the MCP isn't configured for captures), `false`
 * when the per-session Kali-side subtree was missing or harvest
 * otherwise failed — callers surface that as `harvest_warning` in
 * the tool result so the anomaly is visible to the tool caller
 * rather than just buried in MCP stderr (codex pre-push cycle 3
 * finding-2). Never throws.
 *
 * When `runId` is supplied, harvest uses it instead of re-reading
 * the active trace context at close time. Persistent sessions
 * capture their `run_id` at construction time and pass it here, so
 * a scenario rotation during a long-running session does not
 * cause the harvest to look under the wrong run dir (codex
 * pre-push cycle 3 finding-6).
 */
async function maybeHarvest(
  labConfig: LabConfig,
  sessionId: string,
  runId?: string,
): Promise<boolean> {
  const containerName = resolveCaptureContainer(labConfig);
  if (!containerName) return true;
  try {
    return await harvestSession({ containerName, runId }, sessionId);
  } catch (err) {
    console.error('[captures] harvest threw:', err);
    return false;
  }
}

export interface ToolContext {
  sshManager: SSHConnectionManager;
  labConfig: LabConfig;
}

/**
 * Get the shell type from lab configuration
 */
function getShellType(labConfig: LabConfig): ShellType {
  if (!labConfig.containers || !labConfig.server.configKey) {
    return 'bash'; // Default to bash
  }

  const container = labConfig.containers[labConfig.server.configKey];
  return (container?.shell as ShellType) || 'bash';
}

// Argument interfaces for each handler
interface TargetInfoArgs {}

interface RunCommandArgs {
  command: string;
}

interface InteractiveSessionArgs {
  session_id?: string;
  timeout_ms?: number;
}

interface BackgroundSessionArgs {
  session_id?: string;
  raw?: boolean;
  timeout_ms?: number;
}

interface SessionCommandArgs {
  session_id: string;
  command: string;
  timeout?: number;
  raw?: boolean;
}

interface ListSessionsArgs {}

interface CloseSessionArgs {
  session_id: string;
}

interface GetSessionOutputArgs {
  session_id: string;
  lines?: number;
  clear?: boolean;
}

interface CloseAllSessionsArgs {}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- MCP SDK provides untyped args; validated by JSON Schema before reaching handlers
export type ToolHandler = (args: any, context: ToolContext) => Promise<{ content: { type: string; text: string }[] }>;

// Base handler functions — each casts args to its specific interface.
// MCP SDK validates args against the JSON Schema before handlers run,
// so the casts are safe at runtime.
const baseHandlers: Record<string, ToolHandler> = {

  target_info: async (_args, { labConfig }) => {
    if (!labConfig.containers) {
      return {
        content: [
          {
            type: 'text',
            text: `${labConfig.server.targetName} containers not configured - use API tools instead.`,
          },
        ],
      };
    }

    const configKey = labConfig.server.configKey;
    const container = labConfig.containers[configKey];

    if (!container) {
      return {
        content: [
          {
            type: 'text',
            text: `Container '${configKey}' not found in configuration`,
          },
        ],
      };
    }

    if (!container.enabled) {
      return {
        content: [
          {
            type: 'text',
            text: `${labConfig.server.targetName} instance is not enabled in the current lab configuration.`,
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            target_ip: container.container_ip,
            ssh_user: container.ssh_user,
            ssh_port: container.ssh_port,
            lab_name: labConfig.lab.name,
            lab_network: labConfig.lab.network_subnet,
            target_name: labConfig.server.targetName,
            note: `Use ${labConfig.server.targetName} for operations in this container.`,
          }, null, 2),
        },
      ],
    };
  },

  run_command: async (args, { sshManager, labConfig }) => {
    const { command } = args as RunCommandArgs;

    try {
      const credentials = getTargetCredentials(labConfig);

      const result = await sshManager.executeCommand(
        credentials.target,
        credentials.username,
        credentials.sshKey,
        command,
        credentials.port,
      );
      // OBS-003 (codex finding-3): harvest the one-shot exec's
      // captures out of the docker named volume now that the stream
      // has closed. Best-effort; failure logs to stderr and never
      // turns into a tool error.
      await maybeHarvest(labConfig, result.sessionId);

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

  interactive_session: async (args, { sshManager, labConfig }) => {
    const {
      session_id,
      timeout_ms = 600000
    } = args as InteractiveSessionArgs;

    try {
      if (session_id !== undefined) {
        assertSessionIdContract(session_id);
      }
      const finalSessionId = session_id || `session_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const credentials = getTargetCredentials(labConfig);

      const session = await sshManager.createSession(
        finalSessionId,
        credentials.target,
        credentials.username,
        'interactive',
        credentials.sshKey,
        credentials.port,
        'normal',
        timeout_ms,
        getShellType(labConfig)
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
              message: `${labConfig.server.targetName} session '${sessionInfo.sessionId}' created successfully`
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

  background_session: async (args, { sshManager, labConfig }) => {
    const {
      session_id,
      raw = false,
      timeout_ms = 600000
    } = args as BackgroundSessionArgs;

    try {
      if (session_id !== undefined) {
        assertSessionIdContract(session_id);
      }
      const finalSessionId = session_id || `bg_session_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
      const credentials = getTargetCredentials(labConfig);

      const session = await sshManager.createSession(
        finalSessionId,
        credentials.target,
        credentials.username,
        'background',
        credentials.sshKey,
        credentials.port,
        raw ? 'raw' : 'normal',
        timeout_ms,
        getShellType(labConfig)
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
              message: `${labConfig.server.targetName} background session '${sessionInfo.sessionId}' created successfully${raw ? ' (raw mode for interactive programs)' : ''}`
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

  session_command: async (args, { sshManager }) => {
    const { session_id, command, timeout = 30000, raw } = args as SessionCommandArgs;

    try {
      assertSessionIdContract(session_id);
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

  list_sessions: async (_args, { sshManager }) => {
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

  close_session: async (args, { sshManager, labConfig }) => {
    const { session_id } = args as CloseSessionArgs;

    try {
      // Reject MCP-ingress id contract violations through the same
      // catch block as any other tool error so the response envelope
      // is consistent (codex pre-push cycle 3 finding-4 + test-quality
      // followup — the prior precondition outside try threw out of
      // the handler instead of producing a `success: false` envelope).
      assertSessionIdContract(session_id);
      // Snapshot the bound run id BEFORE closeSession removes the
      // session from the manager (codex pre-push cycle 3 finding-6).
      const boundRunId = sshManager.getSessionRunId(session_id);
      const closed = await sshManager.closeSession(session_id);
      // OBS-003: pull this session's captures out of the docker
      // named volume into `.aptl/runs/<run_id>/kali-side/<session_id>/`.
      // Best-effort; runs after closeSession completes so a harvest
      // failure can't leave the session stuck in the manager.
      let harvestWarning: string | undefined;
      if (closed) {
        const ok = await maybeHarvest(labConfig, session_id, boundRunId);
        if (!ok) {
          // Surface the anomaly to the tool caller, not just MCP
          // stderr (codex pre-push cycle 3 finding-2).
          harvestWarning =
            'Kali-side per-session captures missing or unavailable; ' +
            'MCP-side PTY tee + tool-call JSONL remain authoritative.';
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: closed,
              session_id,
              message: closed ? `Session '${session_id}' closed successfully` : `Session '${session_id}' not found`,
              ...(harvestWarning ? { harvest_warning: harvestWarning } : {}),
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

  get_session_output: async (args, { sshManager }) => {
    const { session_id, lines, clear = false } = args as GetSessionOutputArgs;

    try {
      assertSessionIdContract(session_id);
      // Route through the manager so the centralized session-not-found
      // precondition (and any future manager-level guards) cannot be
      // bypassed. The handler's catch block converts the thrown SSHError
      // into the standard error envelope, matching session_command and
      // close_session.
      const output = sshManager.getSessionOutput(session_id, lines, clear);

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

  close_all_sessions: async (_args, { sshManager, labConfig }) => {
    try {
      const sessions = sshManager.listSessions();
      const sessionCount = sessions.length;
      // Snapshot session ids AND their bound run ids BEFORE
      // disconnect — `disconnectAll` clears the manager, so we
      // can't ask for run ids afterwards (codex pre-push cycle 3
      // finding-6).
      const sessionBindings = sessions.map((s) => ({
        sessionId: s.sessionId,
        runId: sshManager.getSessionRunId(s.sessionId),
      }));

      await sshManager.disconnectAll();

      // OBS-003: harvest captures for each session that was active.
      // Best-effort and serial — harvests are small file copies, so
      // sequential is fine and keeps stderr ordering deterministic.
      const harvestWarnings: string[] = [];
      for (const { sessionId, runId } of sessionBindings) {
        const ok = await maybeHarvest(labConfig, sessionId, runId);
        if (!ok) {
          harvestWarnings.push(sessionId);
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: true,
              sessions_closed: sessionCount,
              message: `All ${sessionCount} sessions have been closed`,
              ...(harvestWarnings.length > 0
                ? {
                    harvest_warning:
                      `Kali-side captures missing for sessions: ${harvestWarnings.join(', ')}. ` +
                      'MCP-side PTY tee + tool-call JSONL remain authoritative.',
                  }
                : {}),
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

/**
 * Generate tool handlers with server-specific names
 */
export function generateToolHandlers(serverConfig: LabConfig['server']): Record<string, ToolHandler> {
  const handlers: Record<string, ToolHandler> = {};

  // Map server-specific tool names to base handlers
  handlers[`${serverConfig.toolPrefix}_info`] = baseHandlers.target_info;
  handlers[`${serverConfig.toolPrefix}_run_command`] = baseHandlers.run_command;
  handlers[`${serverConfig.toolPrefix}_interactive_session`] = baseHandlers.interactive_session;
  handlers[`${serverConfig.toolPrefix}_background_session`] = baseHandlers.background_session;
  handlers[`${serverConfig.toolPrefix}_session_command`] = baseHandlers.session_command;
  handlers[`${serverConfig.toolPrefix}_list_sessions`] = baseHandlers.list_sessions;
  handlers[`${serverConfig.toolPrefix}_close_session`] = baseHandlers.close_session;
  handlers[`${serverConfig.toolPrefix}_get_session_output`] = baseHandlers.get_session_output;
  handlers[`${serverConfig.toolPrefix}_close_all_sessions`] = baseHandlers.close_all_sessions;

  return handlers;
}
