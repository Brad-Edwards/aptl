/**
 * OCSF visibility for composite tools (ORC-003 / ADR-045).
 *
 * A composite MCP tool (for example `kali_full_port_scan`) runs one or more
 * internal shell commands but surfaces a single top-level tool call. ADR-045
 * requires those internal commands to stay visible on the red OCSF path —
 * they must not disappear from `ocsf.jsonl` merely because the agent made one
 * top-level call. The composite handler emits each executed command as a
 * `CompositeStepRecord` in its result envelope; this module turns those step
 * records into per-step OCSF emissions, reusing the existing
 * `logRedTeamCommandAsync` sink path (no second logging vocabulary).
 *
 * The raw `tool-calls.jsonl` capture already records the composite call (with
 * its full step-bearing result) via the shared post-tool capture; this module
 * adds the structured per-step OCSF attribution on top.
 */

import type { CompositeStepRecord } from 'aptl-mcp-common';
import {
  logRedTeamCommandAsync,
  type RedTeamCommandContext,
  type SiemSink,
} from './logger.js';

/** Composite tools whose internal commands need per-step OCSF attribution. */
const COMPOSITE_TOOL_SUFFIXES = ['_full_port_scan'] as const;

export function isCompositeTool(toolName: string): boolean {
  return COMPOSITE_TOOL_SUFFIXES.some((suffix) => toolName.endsWith(suffix));
}

/**
 * Pull the `steps[]` array out of a composite tool's result envelope. The
 * composite returns `{ content: [{ type: 'text', text: <json> }] }` where the
 * JSON carries `steps: CompositeStepRecord[]`. Best-effort: any shape that is
 * not a step-bearing composite envelope yields an empty list.
 */
export function extractCompositeSteps(result: unknown): CompositeStepRecord[] {
  try {
    const text = (result as { content?: { text?: unknown }[] })?.content?.[0]?.text;
    if (typeof text !== 'string') return [];
    const parsed = JSON.parse(text) as { steps?: unknown };
    if (!Array.isArray(parsed.steps)) return [];
    return parsed.steps.filter(
      (step): step is CompositeStepRecord =>
        typeof (step as CompositeStepRecord)?.command === 'string' && (step as CompositeStepRecord).command.length > 0,
    );
  } catch {
    return [];
  }
}

/**
 * Build one OCSF emission task per composite step. A step whose outcome is
 * known (a `success` flag is present) emits Success/Failure with its exit
 * code/signal; a step with no observed outcome emits Unknown.
 */
export function ocsfTasksForCompositeSteps(
  toolName: string,
  agentName: string,
  steps: CompositeStepRecord[],
  sink: SiemSink,
): Promise<unknown>[] {
  return steps.map((step) => {
    const context: RedTeamCommandContext = {
      tool_name: toolName,
      agent_name: agentName,
      session_id: step.session_id,
      duration_ms: step.duration_ms,
    };
    if (typeof step.success === 'boolean') {
      context.success = step.success;
      if (typeof step.exit_code === 'number') context.exit_code = step.exit_code;
      if (step.signal) context.signal = step.signal;
    } else {
      context.outcome_unknown = true;
    }
    return logRedTeamCommandAsync(step.command, context, sink);
  });
}
