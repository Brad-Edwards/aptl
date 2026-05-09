/**
 * Red-team SIEM event logger.
 *
 * Builds OCSF-shaped activity records for AI-agent-executed commands and
 * writes them to a sink (default: stderr JSONL with `[OCSF]` sentinel
 * prefix). Per ADR-027:
 *
 *   - Best-effort: classification, extraction, redaction, or sink failures
 *     never bubble out of `logRedTeamCommand`. Errors are reported to
 *     stderr and the call returns `null`.
 *   - Severity values are OCSF `severity_id` 0–6 — matches the Python
 *     `SeverityId` enum in `src/aptl/core/detection.py`.
 *   - The `process.cmd_line` field is the verbatim command after running
 *     it through the shared `redact()` helper from `aptl-mcp-common`.
 *     The logger never invents a second redaction policy.
 */

import { redact } from 'aptl-mcp-common';
import {
  classifyCommand,
  SeverityId,
  type ActivityClassification,
  type SeverityIdValue,
} from './classifier.js';
import { extractMetadata, type ExtractedFields, type OcsfEndpoint } from './extractor.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface RedTeamCommandContext {
  tool_name: string;
  agent_name: string;
  session_id?: string;
  success?: boolean;
  /** Force OCSF status_id=0 (Unknown) when no real outcome was observed. */
  outcome_unknown?: boolean;
  exit_code?: number;
  signal?: string;
  duration_ms?: number;
  src_host?: string;
}

export interface OcsfAttackEntry {
  technique?: { uid: string };
  tactic?: { name: string };
}

export interface OcsfRedTeamRecord {
  /** OCSF `timestamp_t`: milliseconds since Unix epoch. */
  time: number;
  severity_id: SeverityIdValue;
  category_uid: number;
  category_name: string;
  class_uid: number;
  class_name: string;
  activity_id: number;
  type_uid: number;
  metadata: { product: { name: string; vendor_name: string } };
  attacks?: OcsfAttackEntry[];
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  actor?: { user?: { name?: string } };
  process?: { cmd_line: string };
  // OCSF Web Resources Activity / Network Activity fields populated when
  // the extractor surfaces them. Records emitted for non-network commands
  // omit these entirely.
  http_request?: { url: string };
  connection_info?: { protocol_name: string };
  file?: { path: string };
  /** OCSF normalized outcome — 1 Success, 2 Failure, 0 Unknown. */
  status_id?: 0 | 1 | 2;
  /** OCSF normalized outcome label. */
  status?: 'Unknown' | 'Success' | 'Failure';
  /** Source-specific status/exit code (numeric exit code or signal name). */
  status_code?: string;
  duration?: number;
  aptl?: {
    activity_type: string;
    tool?: string;
    tool_name: string;
    agent_name: string;
    session_id?: string;
    exit_code?: number;
    signal?: string;
  };
}

export type SiemSink = (record: OcsfRedTeamRecord) => void | Promise<void>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const PRODUCT_NAME = 'aptl-mcp-red';
export const PRODUCT_VENDOR = 'APTL';
const STDERR_SENTINEL = '[OCSF] ';

// ---------------------------------------------------------------------------
// Default sink
// ---------------------------------------------------------------------------

export const stderrJsonlSink: SiemSink = (record: OcsfRedTeamRecord): void => {
  const line = `${STDERR_SENTINEL}${JSON.stringify(record)}\n`;
  process.stderr.write(line);
};

// ---------------------------------------------------------------------------
// Tool-result success derivation
// ---------------------------------------------------------------------------

export interface CommandOutcome {
  /** True/false when observed; null when we cannot determine outcome
   * from the result envelope (malformed JSON, missing fields, etc.). */
  success: boolean | null;
  exit_code?: number;
  signal?: string;
}

/**
 * Derive command outcome from a tool result envelope.
 *
 * The common handlers expose exit status in two different shapes (per
 * `mcp/aptl-mcp-common/src/tools/handlers.ts`):
 *
 *   - `*_session_command`: top-level `exit_code` (number).
 *   - `*_run_command`:     nested `output.code` on the SSH `CommandResult`
 *                          (`output: { stdout, stderr, code, signal }`).
 *
 * A command terminated by a signal returns `code: null, signal: 'SIGTERM'` —
 * those are command failures, not transport successes. We check, in order:
 *   - thrown error → failure
 *   - top-level `exit_code` (number) → success iff 0
 *   - nested `output.signal` (non-null) → failure
 *   - nested `output.code` (number) → success iff 0
 *   - top-level `success: false` → failure
 *   - default (unknown) → success (best-effort: never invent failures)
 */
function parseEnvelope(toolResult: unknown): Record<string, unknown> | null {
  const content = (toolResult as { content?: { text?: string }[] } | undefined)?.content;
  const text = content?.[0]?.text;
  if (typeof text !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

function outcomeFromNestedOutput(out: unknown): CommandOutcome | null {
  if (typeof out !== 'object' || out === null) return null;
  const outObj = out as Record<string, unknown>;
  const signal = typeof outObj.signal === 'string' ? outObj.signal : undefined;
  const code = typeof outObj.code === 'number' ? outObj.code : undefined;
  if (signal) {
    return { success: false, ...(code === undefined ? {} : { exit_code: code }), signal };
  }
  if (code === undefined) return null;
  return { success: code === 0, exit_code: code };
}

export function deriveCommandOutcome(
  toolResult: unknown,
  error: Error | undefined,
): CommandOutcome {
  if (error) return { success: false };
  try {
    const obj = parseEnvelope(toolResult);
    if (obj === null) return { success: null };
    if (typeof obj.exit_code === 'number') {
      return { success: obj.exit_code === 0, exit_code: obj.exit_code };
    }
    const nested = outcomeFromNestedOutput(obj.output);
    if (nested) return nested;
    if (typeof obj.success === 'boolean') return { success: obj.success };
    return { success: null };
  } catch {
    return { success: null };
  }
}

/**
 * Backward-compatible boolean derivation. Prefer `deriveCommandOutcome`
 * when callers also need the exit code or signal name. Returns `false`
 * for genuine failures AND for unknown-outcome envelopes (defensive
 * default for callers that need a strict boolean).
 */
export function deriveCommandSuccess(toolResult: unknown, error: Error | undefined): boolean {
  return deriveCommandOutcome(toolResult, error).success === true;
}

// ---------------------------------------------------------------------------
// Logger entry point
// ---------------------------------------------------------------------------

/**
 * Build and dispatch an OCSF red-team activity record for `command`.
 *
 * Returns the constructed record, or `null` when the input is unusable
 * (empty / non-string command) or any internal step throws. The function
 * is synchronous-returning by design — callers like the postToolHook
 * receive the record without blocking on a possibly async transport.
 *
 * For an async sink (e.g. HTTP shipping to Wazuh / OpenSearch), pass it
 * to `logRedTeamCommand` and await the returned promise via
 * `logRedTeamCommandAsync` from the postToolHook so common's hook
 * timeout still applies.
 */
export function logRedTeamCommand(
  command: string,
  context: RedTeamCommandContext,
  sink: SiemSink = stderrJsonlSink,
): OcsfRedTeamRecord | null {
  try {
    if (typeof command !== 'string' || !command.trim()) return null;
    const classification = classifyCommand(command);
    const extracted = extractMetadata(command, classification);
    const record = buildOcsfRecord(command, classification, extracted, context);
    invokeSink(sink, record);
    return record;
  } catch (err) {
    console.error('[OCSF] logRedTeamCommand error:', err);
    return null;
  }
}

function effectiveSeverity(
  classification: ActivityClassification,
  context: RedTeamCommandContext,
): SeverityIdValue {
  const base = classification.default_severity_id;
  const failed = context.success === false;
  return failed && base < SeverityId.MEDIUM ? SeverityId.MEDIUM : base;
}

function buildAptlEnvelope(
  classification: ActivityClassification,
  context: RedTeamCommandContext,
): NonNullable<OcsfRedTeamRecord['aptl']> {
  return {
    activity_type: classification.activity_type,
    ...(classification.tool ? { tool: classification.tool } : {}),
    tool_name: context.tool_name,
    agent_name: context.agent_name,
    ...(context.session_id ? { session_id: context.session_id } : {}),
    ...(typeof context.exit_code === 'number' ? { exit_code: context.exit_code } : {}),
    ...(context.signal ? { signal: context.signal } : {}),
  };
}

function attachAttackEntry(
  record: OcsfRedTeamRecord,
  classification: ActivityClassification,
): void {
  if (!classification.technique_uid && !classification.tactic) return;
  const entry: OcsfAttackEntry = {};
  if (classification.technique_uid) entry.technique = { uid: classification.technique_uid };
  if (classification.tactic) entry.tactic = { name: classification.tactic };
  record.attacks = [entry];
}

function attachExtractedFields(record: OcsfRedTeamRecord, extracted: ExtractedFields): void {
  if (extracted.dst_endpoint) record.dst_endpoint = extracted.dst_endpoint;
  if (extracted.src_endpoint) record.src_endpoint = extracted.src_endpoint;
  if (extracted.target_user) record.actor = { user: { name: extracted.target_user } };
  if (extracted.url) {
    const safeUrl = redact(extracted.url);
    record.http_request = { url: typeof safeUrl === 'string' ? safeUrl : extracted.url };
  }
  if (extracted.protocol) record.connection_info = { protocol_name: extracted.protocol };
  if (extracted.file?.path) record.file = { path: extracted.file.path };
}

function attachStatusFields(record: OcsfRedTeamRecord, context: RedTeamCommandContext): void {
  if (typeof context.success === 'boolean') {
    record.status_id = context.success ? 1 : 2;
    record.status = context.success ? 'Success' : 'Failure';
  } else if (context.outcome_unknown === true) {
    record.status_id = 0;
    record.status = 'Unknown';
  }
  if (typeof context.exit_code === 'number') {
    record.status_code = String(context.exit_code);
  } else if (context.signal) {
    record.status_code = context.signal;
  }
  if (typeof context.duration_ms === 'number') record.duration = context.duration_ms;
}

function buildOcsfRecord(
  command: string,
  classification: ActivityClassification,
  extracted: ExtractedFields,
  context: RedTeamCommandContext,
): OcsfRedTeamRecord {
  const record: OcsfRedTeamRecord = {
    time: Date.now(),
    severity_id: effectiveSeverity(classification, context),
    category_uid: classification.category_uid,
    category_name: classification.category_name,
    class_uid: classification.class_uid,
    class_name: classification.class_name,
    activity_id: classification.activity_id,
    type_uid: classification.type_uid,
    metadata: { product: { name: PRODUCT_NAME, vendor_name: PRODUCT_VENDOR } },
    process: { cmd_line: redactCommand(command, classification) },
    aptl: buildAptlEnvelope(classification, context),
  };
  attachAttackEntry(record, classification);
  attachExtractedFields(record, extracted);
  attachStatusFields(record, context);
  return record;
}

function invokeSink(sink: SiemSink, record: OcsfRedTeamRecord): void {
  try {
    const ret = sink(record);
    if (ret && typeof ret.then === 'function') {
      ret.catch((err: unknown) => {
        console.error('[OCSF] sink error:', err);
      });
    }
  } catch (err) {
    console.error('[OCSF] sink error:', err);
  }
}

/**
 * Async-aware variant of `logRedTeamCommand`. Use this from a
 * `postToolHook` whose sink is async (HTTP shipping, queued buffer
 * flushes) so `createMCPServer`'s `postToolHookTimeoutMs` applies.
 *
 * Returns the constructed record after the sink resolves, or `null` on
 * any internal failure. Sink rejections are caught and logged; the
 * record (built before the sink ran) is still returned.
 */
export async function logRedTeamCommandAsync(
  command: string,
  context: RedTeamCommandContext,
  sink: SiemSink = stderrJsonlSink,
): Promise<OcsfRedTeamRecord | null> {
  let record: OcsfRedTeamRecord | null = null;
  try {
    record = logRedTeamCommandWithoutSink(command, context);
    if (record === null) return null;
    await Promise.resolve(sink(record));
    return record;
  } catch (err) {
    console.error('[OCSF] sink error (async):', err);
    return record;
  }
}

/**
 * Internal: build the record without invoking the sink. Used by both the
 * sync and async wrappers so the construction logic isn't duplicated.
 */
function logRedTeamCommandWithoutSink(
  command: string,
  context: RedTeamCommandContext,
): OcsfRedTeamRecord | null {
  // Capture by re-running the sync builder with a no-op sink. This
  // intentionally swallows the sync sink invocation — async callers
  // dispatch their own.
  return logRedTeamCommand(command, context, () => undefined);
}

function redactCommand(command: string, _classification: ActivityClassification): string {
  // All redaction policy lives in `aptl-mcp-common/src/redaction.ts` so
  // the same masking applies at every serialization boundary
  // (OTel spans, OCSF cmd_line, archive snapshots). The common policy
  // covers `Authorization:` / `Bearer`, cookies, URL userinfo, PEM
  // blocks, long credential flags, short `-p` for known credential
  // tools (and their wrappers), and curl/wget `--user user:password`.
  const result = redact(command);
  return typeof result === 'string' ? result : JSON.stringify(result);
}
