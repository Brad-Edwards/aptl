/**
 * Research-grade raw tool-call capture.
 *
 * Companion to the OCSF logger. Where `logger.ts` builds an enriched,
 * structured OCSF event, this module appends a minimal (but redacted)
 * record of every tool call to a JSONL file under the per-run mcp-side
 * directory (OBS-003): `<state_dir>/runs/<trace_id>/mcp-side/tool-calls.jsonl`.
 *
 * Researchers can re-parse the captured stream with their own logic;
 * the raw command, args, and result text are preserved (modulo
 * credential redaction via the shared `redact()` helper, with an
 * experimenter-side opt-out via `APTL_EXPERIMENT_NO_REDACT=1`).
 *
 * When no scenario context is active (no `trace-context.json` in the
 * state dir), capture falls back to the `_unbound` sentinel
 * (`<state_dir>/runs/_unbound/mcp-side/tool-calls.jsonl`) so MCP
 * invocations outside a scenario don't silently drop their record
 * — the sentinel makes the "no active scenario" condition visible.
 *
 * Best-effort: I/O errors never propagate to the caller. The capture
 * sink is async-safe so it composes with the `postToolHook` timeout
 * in `aptl-mcp-common`.
 */

import { appendFile, chmod, mkdir, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  redact,
  mcpSideDir,
  resolveActiveRunDir,
  experimentNoRedactActive,
} from 'aptl-mcp-common';

/**
 * OBS-003 / cycle 3 finding-9: experimental opt-out applied at the
 * local per-run sink only. Returns the value untouched when the
 * experimenter has explicitly set `APTL_EXPERIMENT_NO_REDACT=1`;
 * otherwise routes through the shared `redact()` boundary.
 */
function experimentalRedact(value: unknown, env: NodeJS.ProcessEnv): unknown {
  if (experimentNoRedactActive(env)) return value;
  return redact(value);
}

const TOOL_CALLS_FILE = 'tool-calls.jsonl';
const OCSF_FILE = 'ocsf.jsonl';
const UNBOUND_SENTINEL = '_unbound';

function resolveMcpSideDir(env: NodeJS.ProcessEnv): string {
  const stateDir = env.APTL_STATE_DIR ?? '.aptl';
  const active = resolveActiveRunDir(env);
  if (active) {
    // `<state>/runs/<trace_id>` -> `.../mcp-side`
    return resolve(active, 'mcp-side');
  }
  return mcpSideDir(stateDir, UNBOUND_SENTINEL);
}

/**
 * Resolve the per-run tool-call capture file. Routes by active trace
 * context to the per-run mcp-side directory, falling back to the
 * `_unbound` sentinel when no scenario is active.
 *
 * The pre-OBS-003 `APTL_RED_CAPTURE_PATH` env-var override (an
 * escape hatch originally intended for bind-mounting captures into
 * a SIEM ingester) was removed under ADR-033: no red→SIEM pipe is
 * allowed (codex pre-push cycle 1 finding-8 also surfaced that the
 * override only applied to tool-calls and would split records from
 * OCSF if used).
 */
export function captureFilePath(env: NodeJS.ProcessEnv = process.env): string {
  return resolve(resolveMcpSideDir(env), TOOL_CALLS_FILE);
}

/**
 * Resolve the per-run OCSF JSONL path. Same routing as
 * `captureFilePath` — both flow through `resolveMcpSideDir` so the
 * tool-call and OCSF records can never disagree about which run
 * they belong to (codex finding-8).
 */
export function ocsfFilePath(env: NodeJS.ProcessEnv = process.env): string {
  return resolve(resolveMcpSideDir(env), OCSF_FILE);
}

export interface ToolCallCaptureRecord {
  time: number; // epoch ms
  tool_name: string;
  agent_name: string;
  args: unknown; // redacted
  /** Redacted command result, only when `APTL_RED_CAPTURE_INCLUDE_RESULT=true`. Free-form
   * stdout from red-team tools can contain unlabelled credentials that
   * pattern-based redaction cannot reliably mask, so this is opt-in. */
  result?: unknown;
  error?: string; // redacted error message
  exit_code?: number;
  signal?: string;
  success?: boolean;
  duration_ms: number;
  session_id?: string;
}

export interface CaptureContext {
  toolName: string;
  agentName: string;
  sessionId?: string;
  args: Record<string, unknown>;
  result?: unknown;
  error?: Error;
  exitCode?: number;
  signal?: string;
  success?: boolean;
  durationMs: number;
}

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);

function shouldIncludeResult(env: NodeJS.ProcessEnv): boolean {
  const v = env.APTL_RED_CAPTURE_INCLUDE_RESULT;
  if (typeof v !== 'string') return false;
  return TRUE_VALUES.has(v.toLowerCase());
}

export function buildCaptureRecord(
  ctx: CaptureContext,
  env: NodeJS.ProcessEnv = process.env,
): ToolCallCaptureRecord {
  // OBS-003: this is one of two sanctioned `APTL_EXPERIMENT_NO_REDACT`
  // sinks (the other is `localOcsfJsonlSink` in logger.ts). The
  // experimental record can preserve credentials/secrets verbatim
  // here without affecting OTel/stderr/runstore boundaries. See
  // `experimentNoRedactActive` in aptl-mcp-common/redaction.ts.
  const record: ToolCallCaptureRecord = {
    time: Date.now(),
    tool_name: ctx.toolName,
    agent_name: ctx.agentName,
    args: experimentalRedact(ctx.args, env),
    duration_ms: ctx.durationMs,
  };
  if (ctx.sessionId) record.session_id = ctx.sessionId;
  if (typeof ctx.exitCode === 'number') record.exit_code = ctx.exitCode;
  if (ctx.signal) record.signal = ctx.signal;
  if (typeof ctx.success === 'boolean') record.success = ctx.success;
  if (ctx.error) {
    record.error = String(experimentalRedact(ctx.error.message ?? String(ctx.error), env));
  } else if (ctx.result !== undefined && shouldIncludeResult(env)) {
    // Tool stdout/stderr can contain unlabelled credentials (mimikatz
    // dumps, hashcat cracks, file reads) that the shared redactor
    // cannot reliably mask. Capturing them by default would turn the
    // research file into a credential store. Opt-in only.
    record.result = experimentalRedact(ctx.result, env);
  }
  return record;
}

/**
 * Append `record` as a single JSONL line. Creates the parent
 * directory on first write. All errors are caught and logged to
 * stderr (`[RED-CAPTURE]`); the function never throws.
 */
export async function appendCaptureRecord(
  record: ToolCallCaptureRecord,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const file = captureFilePath(env);
  try {
    // Restrictive permissions: dir 0700, file 0600. The capture file
    // contains agent-targeted attack metadata (target users / hosts /
    // session IDs and, when opted in, raw command output that may
    // contain unlabelled credentials). Other local users on the same
    // host should not be able to read it.
    await mkdir(dirname(file), { recursive: true, mode: 0o700 });
    let needsCreate = false;
    try {
      await stat(file);
    } catch {
      needsCreate = true;
    }
    await appendFile(file, `${JSON.stringify(record)}\n`, { encoding: 'utf-8', mode: 0o600 });
    // Repair permissions whether the file was just created (umask may
    // have widened the mode) or pre-existed (older runs may have
    // created it with the default 0644).
    if (needsCreate || !needsCreate) {
      try {
        await chmod(file, 0o600);
      } catch {
        // Best-effort.
      }
    }
  } catch (err) {
    console.error('[RED-CAPTURE] append failed:', err);
  }
}

/**
 * Convenience wrapper: build and append in one call.
 */
export async function captureToolCall(
  ctx: CaptureContext,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  try {
    const record = buildCaptureRecord(ctx, env);
    await appendCaptureRecord(record, env);
  } catch (err) {
    console.error('[RED-CAPTURE] capture failed:', err);
  }
}
