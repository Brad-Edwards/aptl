/**
 * Per-run directory contract shared with Python `src/aptl/core/runstore.py`.
 *
 * OBS-003 routes all per-scenario captures (MCP-side tool-call JSONL,
 * OCSF records, continuous PTY streams, and the Kali-side audit / pcap
 * / pty / process-accounting artifacts pulled out of the container)
 * into the same per-run tree:
 *
 *   <state_dir>/runs/<trace_id>/
 *     mcp-side/
 *       tool-calls.jsonl
 *       ocsf.jsonl
 *       sessions/<session_id>.jsonl    # continuous PTY tee
 *     kali-side/<session_id>/
 *       pty/   pcap/   audit/   proc-acct/
 *
 * `trace_id` is the natural cross-process correlation key — Python
 * generates it at scenario start, writes it to
 * `<state_dir>/trace-context.json`, and the MCP servers read it from
 * the same file (already done by `loadParentContext` in telemetry.ts).
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Mirrors `_ID_RE` in `runstore.py`. Identifiers become directory
// components, so reject anything that could break out of the tree.
// Leading `_` is allowed so the `_unbound` sentinel (used when MCP
// servers run outside an active scenario context) survives validation.
const ID_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

function validateId(value: unknown, kind: string): string {
  if (typeof value !== 'string' || !ID_RE.test(value)) {
    throw new Error(`invalid ${kind}: ${JSON.stringify(value)}`);
  }
  if (value.includes('..')) {
    // `..` survives the character-class regex but is the canonical
    // traversal segment. Reject defensively.
    throw new Error(`invalid ${kind} (contains '..'): ${JSON.stringify(value)}`);
  }
  return value;
}

function stateDirFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.APTL_STATE_DIR || '.aptl';
}

/**
 * Read `<state_dir>/trace-context.json` and return its `trace_id`
 * if it's present and shape-valid. Returns `undefined` cleanly when
 * no scenario is active, the file is malformed, or `trace_id` is
 * missing / unsafe. Light enough to call from any tool-call hot path
 * (single sync file read; capture sites can cache the result if
 * needed).
 */
export function loadActiveTraceId(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const ctxPath = resolve(stateDirFromEnv(env), 'trace-context.json');
  if (!existsSync(ctxPath)) return undefined;
  let raw: string;
  try {
    raw = readFileSync(ctxPath, 'utf-8');
  } catch {
    return undefined;
  }
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof data !== 'object' || data === null) return undefined;
  const tid = (data as Record<string, unknown>).trace_id;
  if (typeof tid !== 'string') return undefined;
  try {
    validateId(tid, 'trace_id');
  } catch {
    return undefined;
  }
  return tid;
}

/**
 * Resolve `<state_dir>/runs/<trace_id>` for the active scenario.
 * Returns `undefined` when no scenario is active (caller decides
 * whether to fall back to an `_unbound` sentinel or skip).
 */
export function resolveActiveRunDir(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const tid = loadActiveTraceId(env);
  if (!tid) return undefined;
  return resolve(stateDirFromEnv(env), 'runs', tid);
}

/** `<state_dir>/runs/<run_id>/mcp-side` */
export function mcpSideDir(stateDir: string, runId: string): string {
  return resolve(stateDir, 'runs', validateId(runId, 'run_id'), 'mcp-side');
}

/** `<state_dir>/runs/<run_id>/kali-side/<session_id>` */
export function kaliSideSessionDir(stateDir: string, runId: string, sessionId: string): string {
  return resolve(
    stateDir,
    'runs',
    validateId(runId, 'run_id'),
    'kali-side',
    validateId(sessionId, 'session_id')
  );
}

/** `<state_dir>/runs/<run_id>/mcp-side/sessions/<session_id>.jsonl` */
export function mcpSessionJsonl(stateDir: string, runId: string, sessionId: string): string {
  return resolve(
    mcpSideDir(stateDir, runId),
    'sessions',
    `${validateId(sessionId, 'session_id')}.jsonl`
  );
}

/**
 * Direction of a PTY chunk relative to the agent's view: bytes flowing
 * back to the agent (`out` for stdout, `err` for stderr). We do not
 * tee bytes flowing *into* the shell because the MCP server's
 * tool-call args already record the command text — duplicating it in
 * the PTY JSONL would just add noise.
 */
export type PtyChunkDirection = 'out' | 'err';

export interface PtyTeeRecord {
  /** Epoch milliseconds. */
  ts: number;
  /** Out (stdout) or err (stderr) — agent-perspective output direction. */
  dir: PtyChunkDirection;
  /** Base64-encoded raw bytes from the SSH PTY. Base64 preserves
   * non-UTF-8 bytes (binary tool output, terminal escape sequences)
   * that would be lossy if stored as a JS string. */
  b64: string;
}

export interface PtyTeeWriter {
  (dir: PtyChunkDirection, bytes: Buffer | Uint8Array): void;
  /**
   * Resolve when every chunk handed to the writer so far has been
   * flushed to disk (or has failed and been logged). Provided so
   * tests and explicit-quiesce code paths can await drain instead
   * of guessing a `setTimeout`. Production code typically does NOT
   * need to call this — the writer is fires-and-logs by design.
   */
  flush(): Promise<void>;
}

/**
 * Build a best-effort PTY tee writer for one SSH session. The
 * returned function appends each byte chunk to the per-run JSONL at
 * `<state>/runs/<trace_id>/mcp-side/sessions/<session_id>.jsonl` —
 * or to the `_unbound` sentinel directory when no scenario context
 * is active.
 *
 * OBS-003: this is the MCP-side "continuous tee" that closes the
 * chunk-loss gap in `PersistentSession`. Bytes arriving from the
 * shell stream are recorded as they arrive, independent of which
 * tool-call response (`kali_get_session_output` / `kali_session_command`)
 * the caller eventually polls for them.
 *
 * Best-effort: a write failure is logged to stderr and the writer
 * resolves without throwing. Async I/O does not block the caller —
 * the returned writer fires-and-logs. Tests that need to assert
 * post-write state should `await writer.flush()` (test-quality
 * review cycle 1 finding-6 — fixed-delay `setTimeout` flushes are
 * flaky under CI load).
 */
export function createPtyTeeWriter(
  sessionId: string,
  env: NodeJS.ProcessEnv = process.env,
): PtyTeeWriter {
  // Resolve the file path eagerly once per session: the trace context
  // can in principle change between sessions but is stable for the
  // life of a single session (the SSH connection is opened under one
  // trace_id and survives there).
  const stateDir = env.APTL_STATE_DIR || '.aptl';
  const tid = loadActiveTraceId(env) ?? '_unbound';
  // Tolerate session ids that fail strict validation by falling back
  // to `_invalid`. We don't want PTY capture to swallow a stream
  // because the upstream id format drifted.
  let resolvedSessionId: string;
  try {
    resolvedSessionId = validateId(sessionId, 'session_id');
  } catch {
    resolvedSessionId = '_invalid';
  }
  const file = mcpSessionJsonl(stateDir, tid, resolvedSessionId);

  let dirEnsured = false;
  // Serialize all writes through one promise chain so concurrent `data`
  // events on the SSH stream cannot reorder JSONL lines. Without this,
  // a burst of three `stream.emit('data', ...)` calls each kicks off an
  // independent async write; the order in which `appendFile` resolves
  // is undefined, and the JSONL ends up shuffled.
  let writeQueue: Promise<void> = Promise.resolve();
  const writer = ((dir: PtyChunkDirection, bytes: Buffer | Uint8Array): void => {
    // Synchronous build of the record so the chronological order is
    // captured at the moment of the data event (Date.now() / b64
    // computed under the caller's stack), not at the moment the queued
    // write fires.
    const record: PtyTeeRecord = {
      ts: Date.now(),
      dir,
      b64: Buffer.from(bytes).toString('base64'),
    };
    const line = `${JSON.stringify(record)}\n`;
    writeQueue = writeQueue
      .then(async () => {
        if (!dirEnsured) {
          const { mkdir } = await import('node:fs/promises');
          const { dirname } = await import('node:path');
          await mkdir(dirname(file), { recursive: true, mode: 0o700 });
          dirEnsured = true;
        }
        const { appendFile, chmod } = await import('node:fs/promises');
        await appendFile(file, line, { encoding: 'utf-8', mode: 0o600 });
        try {
          await chmod(file, 0o600);
        } catch {
          // Best-effort permission repair.
        }
      })
      .catch((err) => {
        // Best-effort: log and reset the chain so a single failure
        // doesn't poison subsequent writes.
        console.error('[PTY-TEE] append failed:', err);
      });
  }) as PtyTeeWriter;
  writer.flush = (): Promise<void> => writeQueue;
  return writer;
}
