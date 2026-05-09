/**
 * Research-grade raw tool-call capture.
 *
 * Companion to the OCSF logger. Where `logger.ts` builds an enriched,
 * structured-but-lossy SIEM event, this module appends a minimal
 * (but redacted) record of every tool call to a JSONL file under
 * `<APTL_STATE_DIR>/red-tool-calls.jsonl`. Researchers can re-parse
 * the captured stream with their own logic in pandas/notebooks; the
 * raw command, args, and result text are preserved (modulo
 * credential redaction via the shared `redact()` helper).
 *
 * Best-effort: I/O errors never propagate to the caller. The capture
 * sink is async-safe so it composes with the `postToolHook` timeout
 * in `aptl-mcp-common`.
 */

import { appendFile, chmod, mkdir, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { redact } from 'aptl-mcp-common';

const DEFAULT_FILE_NAME = 'red-tool-calls.jsonl';

/**
 * Resolve the path to the capture file. Honours `APTL_STATE_DIR`
 * (the same env var used by `loadParentContext` in common's telemetry)
 * so the capture lands next to other run artifacts. Override with
 * `APTL_RED_CAPTURE_PATH` if a different location is needed (e.g. a
 * bind-mount into the wazuh-manager container for SIEM ingestion).
 */
export function captureFilePath(env: NodeJS.ProcessEnv = process.env): string {
  const explicit = env.APTL_RED_CAPTURE_PATH;
  if (explicit) return resolve(explicit);
  const stateDir = env.APTL_STATE_DIR ?? '.aptl';
  return resolve(stateDir, DEFAULT_FILE_NAME);
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
  const record: ToolCallCaptureRecord = {
    time: Date.now(),
    tool_name: ctx.toolName,
    agent_name: ctx.agentName,
    args: redact(ctx.args),
    duration_ms: ctx.durationMs,
  };
  if (ctx.sessionId) record.session_id = ctx.sessionId;
  if (typeof ctx.exitCode === 'number') record.exit_code = ctx.exitCode;
  if (ctx.signal) record.signal = ctx.signal;
  if (typeof ctx.success === 'boolean') record.success = ctx.success;
  if (ctx.error) {
    record.error = String(redact(ctx.error.message ?? String(ctx.error)));
  } else if (ctx.result !== undefined && shouldIncludeResult(env)) {
    // Tool stdout/stderr can contain unlabelled credentials (mimikatz
    // dumps, hashcat cracks, file reads) that the shared redactor
    // cannot reliably mask. Capturing them by default would turn the
    // research file into a credential store. Opt-in only.
    record.result = redact(ctx.result);
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
