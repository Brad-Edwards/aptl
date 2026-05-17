#!/usr/bin/env node
/**
 * APTL Kali Red Team MCP Server.
 *
 * Wires the shared MCP server's `postToolHook` (ADR-027, amended by
 * ADR-033 / OBS-003) so that AI-agent-executed Kali commands emit
 * OCSF-shaped activity events to the per-run experimental record.
 * The default composite sink writes to stderr (local dev visibility)
 * and to `<state>/runs/<trace_id>/mcp-side/ocsf.jsonl` — NOT to the
 * blue defensive stack's SIEM (non-contamination principle). Logging
 * is best-effort — classifier/extractor/sink errors never break
 * command execution.
 */
import { startServer, type PostToolHookInfo } from 'aptl-mcp-common';
import { captureToolCall, type CaptureContext } from './capture.js';
import { topLevelSegments } from './classifier.js';
import {
  defaultRedTeamSinks,
  deriveCommandOutcome,
  logRedTeamCommandAsync,
  type CommandOutcome,
  type RedTeamCommandContext,
  type SiemSink,
} from './logger.js';

const AGENT_NAME = 'aptl-kali-red';
const COMMAND_TOOL_SUFFIXES = ['_run_command', '_session_command'] as const;

function isCommandTool(toolName: string): boolean {
  return COMMAND_TOOL_SUFFIXES.some((suffix) => toolName.endsWith(suffix));
}

/**
 * Resolve the session id for capture/OCSF correlation. Prefer the
 * explicit `args.session_id` (persistent session handlers); fall
 * back to the synthetic `exec-...` id the one-shot run_command path
 * generates in `SSHConnectionManager.executeCommand` and surfaces
 * back in `result.output.sessionId` (codex pre-push cycle 3
 * finding-5). Without this fallback, run_command's tool-call JSONL
 * + OCSF records ship without a session id, leaving no join key to
 * the per-run mcp-side PTY tee or kali-side captures.
 */
function extractSessionId(info: PostToolHookInfo): string | undefined {
  const fromArgs = (info.args as { session_id?: string }).session_id;
  if (typeof fromArgs === 'string' && fromArgs.length > 0) return fromArgs;
  // run_command returns { target, command, username, success, output }.
  // `output` is the underlying CommandResult, which now carries
  // `sessionId` per OBS-003 / cycle 1 finding-3.
  const result = info.result as { output?: { sessionId?: string } } | undefined;
  return result?.output?.sessionId;
}

function captureContextFor(
  info: PostToolHookInfo,
  outcome: CommandOutcome,
  outcomeKnown: boolean,
): CaptureContext {
  const sessionId = extractSessionId(info);
  const base: CaptureContext = {
    toolName: info.toolName,
    agentName: AGENT_NAME,
    sessionId,
    args: info.args,
    durationMs: info.durationMs,
  };
  if (info.error) base.error = info.error;
  else if (info.result !== undefined) base.result = info.result;
  if (outcomeKnown) {
    if (typeof outcome.exit_code === 'number') base.exitCode = outcome.exit_code;
    if (outcome.signal) base.signal = outcome.signal;
    base.success = outcome.success === true;
  }
  return base;
}

function ocsfContextForSegment(
  toolName: string,
  sessionId: string | undefined,
  durationMs: number,
  outcome: CommandOutcome,
  outcomeAppliesHere: boolean,
): RedTeamCommandContext {
  const ctx: RedTeamCommandContext = {
    tool_name: toolName,
    agent_name: AGENT_NAME,
    session_id: sessionId,
    duration_ms: durationMs,
  };
  if (outcomeAppliesHere) {
    ctx.success = outcome.success === true;
    if (typeof outcome.exit_code === 'number') ctx.exit_code = outcome.exit_code;
    if (outcome.signal) ctx.signal = outcome.signal;
  } else {
    ctx.outcome_unknown = true;
  }
  return ctx;
}

function ocsfTasksForCommand(
  toolName: string,
  command: string,
  sessionId: string | undefined,
  durationMs: number,
  outcome: CommandOutcome,
  outcomeKnown: boolean,
  sink: SiemSink,
): Promise<unknown>[] {
  const segments = topLevelSegments(command);
  const lastIdx = segments.length - 1;
  return segments.map((segment, segIdx) => {
    const outcomeAppliesHere = segIdx === lastIdx && outcomeKnown;
    return logRedTeamCommandAsync(
      segment,
      ocsfContextForSegment(toolName, sessionId, durationMs, outcome, outcomeAppliesHere),
      sink,
    );
  });
}

// Build the composite OCSF sink once per process — it reads
// `APTL_STATE_DIR` lazily on each invocation through `ocsfFilePath`,
// so trace-context changes between tool calls are picked up. The
// closure itself is cheap to retain.
const ocsfSink = defaultRedTeamSinks();

async function postToolHook(info: PostToolHookInfo): Promise<void> {
  const { toolName, args, durationMs } = info;
  const sessionId = extractSessionId(info);
  const isRawSessionCommand = (args as { raw?: boolean }).raw === true;
  const outcome = deriveCommandOutcome(info.result, info.error);
  const outcomeKnown = !isRawSessionCommand && outcome.success !== null;

  const captureTask = captureToolCall(captureContextFor(info, outcome, outcomeKnown));

  const ocsfTasks: Promise<unknown>[] = [];
  if (isCommandTool(toolName)) {
    const command = (args as { command?: string }).command;
    if (typeof command === 'string' && command) {
      ocsfTasks.push(
        ...ocsfTasksForCommand(
          toolName,
          command,
          sessionId,
          durationMs,
          outcome,
          outcomeKnown,
          ocsfSink,
        ),
      );
    }
  }
  // Run both sinks independently — a slow capture must not delay or
  // starve the OCSF emission and vice versa.
  await Promise.allSettled([captureTask, ...ocsfTasks]);
}

try {
  await startServer(import.meta.url, { postToolHook });
} catch (error) {
  console.error('[MCP] Fatal error:', error);
  process.exit(1);
}
