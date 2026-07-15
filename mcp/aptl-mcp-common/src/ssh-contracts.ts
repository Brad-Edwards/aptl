
import { loadActiveTraceId } from './runs.js';
import { redact } from './redaction.js';
import type { ShellType } from './shells.js';

// Mask embedded credentials before putting a command into an error message.
// Command-timeout / failure SSHError strings can reach stderr (console.error)
// or a raw rejection ahead of the MCP serialization boundary's redaction, so
// `hydra -p hunter2 …` would otherwise leak the password (ARCH-386-08 /
// sec-02). `redact` leaves credential-free commands intact for debugging.
export function redactCommand(command: string): string {
  return redact(command) as string;
}

/**
 * OBS-003: env vars passed to the SSH shell via `SendEnv`/`shell({env})`
 * so anything captured on the Kali side (auditd events, shell typescript,
 * pcaps) can be joined back to the MCP-side scenario run by
 * timestamp + APTL_SESSION_ID. The Kali sshd_config must list
 * `AcceptEnv APTL_*` for these to actually arrive in the shell.
 *
 * - `APTL_RUN_ID`: scenario run identifier (mirrors `trace_id` so it
 *   joins both MCP-side and OTel-side captures).
 * - `APTL_TRACE_ID`: same value, kept as an explicit alias for future
 *   OTel context propagation into the Kali shell.
 * - `APTL_SESSION_ID`: the MCP-level SSH session id.
 */
export function aptlShellEnv(sessionId: string, env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const result: Record<string, string> = { APTL_SESSION_ID: sessionId };
  const tid = loadActiveTraceId(env);
  if (tid) {
    result.APTL_RUN_ID = tid;
    result.APTL_TRACE_ID = tid;
  }
  return result;
}

// Contract helpers. Internal to this module; intentionally not exported.
// `require_` guards caller-facing preconditions and preserves the existing
// throw messages so external substring matchers (tests, MCP envelopes) still
// hit the same text. `ensure` guards callee-side postconditions; the
// `[contract]` prefix is a debugging-aid signal, never a separate error type.
// Both throw the existing `SSHError` per ADR-004 §"Update (2026-05-12)".
export function require_(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new SSHError(message);
  }
}

export function ensure(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new SSHError(`[contract] ${message}`);
  }
}

// Constants for timeouts and limits
export const TIMEOUTS = {
  DEFAULT_COMMAND: 30000,
  DEFAULT_SESSION: 600000,
  CONNECTION: 30000,
  KEEP_ALIVE_INTERVAL: 30000,
  FORCE_CLOSE: 3000,
  SESSION_CLOSE: 5000,
  // #304: close() awaits the SSH stream's remote 'close' event before
  // returning so harvest does not race the wrapper's EXIT trap. If the
  // remote never fires close (channel torn down forcibly, ssh2 bug),
  // we log a [SSH] warning and return anyway — local cleanup is already
  // verified, so the manager's bookkeeping is unaffected.
  REMOTE_CLOSE_AWAIT: 3000,
} as const;

export const BUFFER_LIMITS = {
  MAX_SIZE: 10000,
  TRIM_TO: 5000,
} as const;

export const SSH_CONFIG = {
  READY_TIMEOUT: 30000,
  KEEPALIVE_INTERVAL: 30000,
  KEEPALIVE_COUNT_MAX: 3,
} as const;

export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number | null;
  signal: string | null;
  /**
   * Effective execution mode for this command (#282). `raw` carries the
   * unknown-outcome signal — observability layers (mcp-red OCSF emitter,
   * tool-call JSONL) consume this rather than guessing from `args.raw`,
   * which misses inherited-raw sessions whose command omitted the override.
   */
  mode: SessionMode;
}

export class SSHError extends Error {
  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'SSHError';
    this.cause = cause;
  }
}

export type SessionType = 'interactive' | 'background';
export type SessionMode = 'normal' | 'raw';

export interface SessionConnectOptions {
  port?: number;
  mode?: SessionMode;
  timeoutMs?: number;
  shellType?: ShellType;
}

export interface SessionMetadata {
  sessionId: string;
  target: string;
  username: string;
  type: SessionType;
  mode: SessionMode;
  createdAt: Date;
  lastActivity: Date;
  port: number;
  workingDirectory: string;
  environmentVars: Map<string, string>;
  isActive: boolean;
  commandHistory: string[];
}

export interface CommandRequest {
  id: string;
  command: string;
  resolve: (result: CommandResult) => void;
  reject: (error: Error) => void;
  timeout?: number;
  raw?: boolean;
}
