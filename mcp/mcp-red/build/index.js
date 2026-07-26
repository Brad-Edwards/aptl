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
import { startServer } from 'aptl-mcp-common';
import { captureToolCall } from './capture.js';
import { topLevelSegments } from './classifier.js';
import { isEffectiveRawCall, isOutcomeKnown } from './effective-mode.js';
import { defaultRedTeamSinks, deriveCommandOutcome, logRedTeamCommandAsync, } from './logger.js';
const AGENT_NAME = 'aptl-kali-red';
const COMMAND_TOOL_SUFFIXES = ['_run_command', '_session_command'];
function isCommandTool(toolName) {
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
function extractSessionId(info) {
    const fromArgs = info.args.session_id;
    if (typeof fromArgs === 'string' && fromArgs.length > 0)
        return fromArgs;
    // run_command returns { target, command, username, success, output }.
    // `output` is the underlying CommandResult, which now carries
    // `sessionId` per OBS-003 / cycle 1 finding-3.
    const result = info.result;
    return result?.output?.sessionId;
}
function captureContextFor(info, outcome, outcomeKnown) {
    const sessionId = extractSessionId(info);
    const base = {
        toolName: info.toolName,
        agentName: AGENT_NAME,
        sessionId,
        args: info.args,
        durationMs: info.durationMs,
    };
    if (info.error)
        base.error = info.error;
    else if (info.result !== undefined)
        base.result = info.result;
    if (outcomeKnown) {
        if (typeof outcome.exit_code === 'number')
            base.exitCode = outcome.exit_code;
        if (outcome.signal)
            base.signal = outcome.signal;
        base.success = outcome.success === true;
    }
    return base;
}
function ocsfContextForSegment(toolName, sessionId, durationMs, outcome, outcomeAppliesHere) {
    const ctx = {
        tool_name: toolName,
        agent_name: AGENT_NAME,
        session_id: sessionId,
        duration_ms: durationMs,
    };
    if (outcomeAppliesHere) {
        ctx.success = outcome.success === true;
        if (typeof outcome.exit_code === 'number')
            ctx.exit_code = outcome.exit_code;
        if (outcome.signal)
            ctx.signal = outcome.signal;
    }
    else {
        ctx.outcome_unknown = true;
    }
    return ctx;
}
function ocsfTasksForCommand(toolName, command, sessionId, durationMs, outcome, outcomeKnown, sink) {
    const segments = topLevelSegments(command);
    const lastIdx = segments.length - 1;
    return segments.map((segment, segIdx) => {
        const outcomeAppliesHere = segIdx === lastIdx && outcomeKnown;
        return logRedTeamCommandAsync(segment, ocsfContextForSegment(toolName, sessionId, durationMs, outcome, outcomeAppliesHere), sink);
    });
}
// Build the composite OCSF sink once per process — it reads
// `APTL_STATE_DIR` lazily on each invocation through `ocsfFilePath`,
// so trace-context changes between tool calls are picked up. The
// closure itself is cheap to retain.
const ocsfSink = defaultRedTeamSinks();
async function postToolHook(info) {
    const { toolName, args, durationMs } = info;
    const sessionId = extractSessionId(info);
    // #282: read effective raw mode from the result envelope (which captures
    // the inherited-raw case), not from args.raw alone. The helper falls
    // back to args.raw for compatibility with older common builds.
    const isRawSessionCommand = isEffectiveRawCall(info);
    const outcome = deriveCommandOutcome(info.result, info.error);
    // Raw-mode Unknown ONLY suppresses the transport exit_code: 0 artifact.
    // Handler-level KNOWN failures (errors, success:false envelopes) stay
    // known so OCSF emits Failure, not Unknown. Codex review cycle 2 / D-001.
    const outcomeKnown = isOutcomeKnown(info.error !== undefined, outcome.success, isRawSessionCommand);
    const captureTask = captureToolCall(captureContextFor(info, outcome, outcomeKnown));
    const ocsfTasks = [];
    if (isCommandTool(toolName)) {
        const command = args.command;
        if (typeof command === 'string' && command) {
            ocsfTasks.push(...ocsfTasksForCommand(toolName, command, sessionId, durationMs, outcome, outcomeKnown, ocsfSink));
        }
    }
    // Run both sinks independently — a slow capture must not delay or
    // starve the OCSF emission and vice versa.
    await Promise.allSettled([captureTask, ...ocsfTasks]);
}
try {
    await startServer(import.meta.url, { postToolHook });
}
catch (error) {
    console.error('[MCP] Fatal error:', error);
    process.exit(1);
}
