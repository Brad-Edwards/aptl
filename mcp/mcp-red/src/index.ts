#!/usr/bin/env node
/**
 * APTL Kali Red Team MCP Server.
 *
 * Wires the shared MCP server's `postToolHook` (ADR-027) so that
 * AI-agent-executed Kali commands emit OCSF-shaped activity events to the
 * SIEM stream. Logging is best-effort — classifier/extractor/sink errors
 * never break command execution.
 */
import { startServer } from 'aptl-mcp-common';
import { captureToolCall } from './capture.js';
import { topLevelSegments } from './classifier.js';
import {
  deriveCommandOutcome,
  logRedTeamCommandAsync,
  stderrJsonlSink,
} from './logger.js';

const AGENT_NAME = 'aptl-kali-red';

const COMMAND_TOOL_SUFFIXES = ['_run_command', '_session_command'] as const;

function isCommandTool(toolName: string): boolean {
  return COMMAND_TOOL_SUFFIXES.some((suffix) => toolName.endsWith(suffix));
}

startServer(import.meta.url, {
  // Async hook so common's `postToolHookTimeoutMs` covers both sinks.
  // Sidecar capture and OCSF emission are independent: the sidecar
  // runs for EVERY tool call (raw research data), and the OCSF logger
  // only fires for command-bearing tools (SIEM correlation).
  postToolHook: async ({ toolName, args, result, durationMs, error }) => {
    const sessionId = (args as { session_id?: string }).session_id;
    const isRawSessionCommand = (args as { raw?: boolean }).raw === true;
    const outcome = deriveCommandOutcome(result, error);

    const outcomeKnown = !isRawSessionCommand && outcome.success !== null;

    // Research-grade sidecar: every tool call lands in the JSONL
    // capture file, regardless of whether it carries a command.
    const captureTask = captureToolCall({
      toolName,
      agentName: AGENT_NAME,
      sessionId,
      args,
      ...(error ? { error } : { result }),
      ...(outcomeKnown
        ? {
            ...(typeof outcome.exit_code === 'number' ? { exitCode: outcome.exit_code } : {}),
            ...(outcome.signal ? { signal: outcome.signal } : {}),
            success: outcome.success === true,
          }
        : {}),
      durationMs,
    });

    // SIEM emission: only command-bearing tools. Compound commands
    // like `cd /tmp && nmap -p 22 host` are split into top-level
    // segments and ONE OCSF record per segment is emitted, so the
    // nmap activity is not dropped because it followed a shell
    // builtin. The transport outcome (exit_code / success) applies to
    // the LAST segment that ran; earlier segments emit an Unknown
    // status because we cannot distinguish per-segment outcomes from
    // a single MCP transport result.
    const ocsfTasks: Promise<unknown>[] = [];
    if (isCommandTool(toolName)) {
      const command = (args as { command?: string }).command;
      if (typeof command === 'string' && command) {
        const segments = topLevelSegments(command);
        const lastIdx = segments.length - 1;
        for (let segIdx = 0; segIdx < segments.length; segIdx++) {
          const isLastSegment = segIdx === lastIdx;
          const outcomeAppliesHere = isLastSegment && outcomeKnown;
          ocsfTasks.push(
            logRedTeamCommandAsync(
              segments[segIdx],
              {
                tool_name: toolName,
                agent_name: AGENT_NAME,
                session_id: sessionId,
                ...(outcomeAppliesHere
                  ? {
                      success: outcome.success === true,
                      ...(typeof outcome.exit_code === 'number'
                        ? { exit_code: outcome.exit_code }
                        : {}),
                      ...(outcome.signal ? { signal: outcome.signal } : {}),
                    }
                  : { outcome_unknown: true }),
                duration_ms: durationMs,
              },
              stderrJsonlSink,
            ),
          );
        }
      }
    }

    // Run both sinks independently — a slow capture must not delay or
    // starve the OCSF emission and vice versa.
    await Promise.allSettled([captureTask, ...ocsfTasks]);
  },
}).catch((error) => {
  console.error('[MCP] Fatal error:', error);
  process.exit(1);
});
