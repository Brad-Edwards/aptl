#!/usr/bin/env node
/**
 * APTL Kali Red Team MCP Server.
 *
 * Wires the shared MCP server's `postToolHook` (ADR-027) so that
 * AI-agent-executed Kali commands emit OCSF-shaped activity events to the
 * SIEM stream. Logging is best-effort — classifier/extractor/sink errors
 * never break command execution.
 */
import { startServer, type PostToolHookInfo } from 'aptl-mcp-common';
import { captureToolCall, type CaptureContext } from './capture.js';
import { topLevelSegments } from './classifier.js';
import {
  deriveCommandOutcome,
  logRedTeamCommandAsync,
  stderrJsonlSink,
  type CommandOutcome,
  type RedTeamCommandContext,
} from './logger.js';

const AGENT_NAME = 'aptl-kali-red';
const COMMAND_TOOL_SUFFIXES = ['_run_command', '_session_command'] as const;

function isCommandTool(toolName: string): boolean {
  return COMMAND_TOOL_SUFFIXES.some((suffix) => toolName.endsWith(suffix));
}

function captureContextFor(
  info: PostToolHookInfo,
  outcome: CommandOutcome,
  outcomeKnown: boolean,
): CaptureContext {
  const sessionId = (info.args as { session_id?: string }).session_id;
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
): Promise<unknown>[] {
  const segments = topLevelSegments(command);
  const lastIdx = segments.length - 1;
  return segments.map((segment, segIdx) => {
    const outcomeAppliesHere = segIdx === lastIdx && outcomeKnown;
    return logRedTeamCommandAsync(
      segment,
      ocsfContextForSegment(toolName, sessionId, durationMs, outcome, outcomeAppliesHere),
      stderrJsonlSink,
    );
  });
}

async function postToolHook(info: PostToolHookInfo): Promise<void> {
  const { toolName, args, durationMs } = info;
  const sessionId = (args as { session_id?: string }).session_id;
  const isRawSessionCommand = (args as { raw?: boolean }).raw === true;
  const outcome = deriveCommandOutcome(info.result, info.error);
  const outcomeKnown = !isRawSessionCommand && outcome.success !== null;

  const captureTask = captureToolCall(captureContextFor(info, outcome, outcomeKnown));

  const ocsfTasks: Promise<unknown>[] = [];
  if (isCommandTool(toolName)) {
    const command = (args as { command?: string }).command;
    if (typeof command === 'string' && command) {
      ocsfTasks.push(
        ...ocsfTasksForCommand(toolName, command, sessionId, durationMs, outcome, outcomeKnown),
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
