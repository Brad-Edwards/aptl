
import { Client, ClientChannel } from 'ssh2';
import { readFile } from 'fs/promises';
import { EventEmitter } from 'events';
import { randomBytes } from 'node:crypto';
import { ShellFormatter, ShellType, createShellFormatter } from './shells.js';
import { createPtyTeeWriter, loadActiveTraceId } from './runs.js';

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
function aptlShellEnv(sessionId: string, env: NodeJS.ProcessEnv = process.env): Record<string, string> {
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
function require_(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new SSHError(message);
  }
}

function ensure(condition: boolean, message: string): asserts condition {
  if (!condition) {
    throw new SSHError(`[contract] ${message}`);
  }
}

// Constants for timeouts and limits
const TIMEOUTS = {
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

const BUFFER_LIMITS = {
  MAX_SIZE: 10000,
  TRIM_TO: 5000,
} as const;

const SSH_CONFIG = {
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

interface ConnectionInfo {
  client: Client;
  connected: boolean;
}

export class PersistentSession extends EventEmitter {
  private shell: ClientChannel | null = null;
  private outputBuffer: string[] = [];
  private commandQueue: CommandRequest[] = [];
  private currentCommand: CommandRequest | null = null;
  private sessionInfo: SessionMetadata;
  private client: Client;
  private commandDelimiter: string;
  private keepAliveInterval: NodeJS.Timeout | null = null;
  private sessionTimeout: NodeJS.Timeout | null = null;
  private commandTimeout: NodeJS.Timeout | null = null;
  private isInitialized = false;
  private outputData = '';
  private shellFormatter: ShellFormatter;
  // Durable cleanup-success latch shared by both emit sites (close() and
  // stream.on('close')). cleanupVerified flips to true exactly once, when
  // doCleanup + assertCleanupInvariants both complete without throwing.
  // closedEmitted enforces once-only emission so a late async stream-close
  // following a successful close() cannot double-fire. Together they replace
  // the fragile explicitClose flag from cycle 2 — explicitClose only covers
  // the synchronous window of close()'s stack, but ssh2's shell.end() can
  // emit 'close' arbitrarily later. (Codex pre-push cycle 3, ADR-004.)
  private cleanupVerified = false;
  private closedEmitted = false;
  // #304: latched promise that resolves when the SSH stream's remote
  // 'close' event fires. close() awaits this before returning so the
  // post-close harvest does not race the kali wrapper's EXIT trap.
  // Built once in initialize() and never replaced — re-binding it would
  // break the "stream-driven close (unsolicited)" path that relies on a
  // single resolver.
  private remoteClosed: Promise<void> = Promise.resolve();
  private resolveRemoteClosed: () => void = () => {};

  // Stored alongside the formatter so it's externally inspectable
  // (test-quality review cycle 1 finding-2/3/4 — the shellType
  // constructor parameter was previously consumed into the
  // formatter only, so a regression that ignored it could not be
  // detected by inspecting the session).
  private readonly shellType: ShellType;

  // OBS-003: per-session PTY tee — writes every byte received from
  // the SSH PTY into a per-run JSONL independent of which tool-call
  // response eventually drains the bytes from `outputBuffer`. Lazily
  // built in `initialize()` so the writer's filesystem resolution
  // can read the trace context at the moment the session opens.
  private ptyTee: import('./runs.js').PtyTeeWriter | null = null;
  // OBS-003: trace id captured at session open. The Kali wrapper's
  // SendEnv-supplied `APTL_RUN_ID` pins the per-session capture
  // directory under THIS trace id, even if the scenario is later
  // cleared or rotated. The MCP-side harvest reads this rather than
  // the ambient trace context (codex pre-push cycle 3 finding-6).
  private boundRunId: string | undefined;

  private sessionTimeoutMs: number;

  private clearCommandTimeout(): void {
    if (this.commandTimeout) {
      clearTimeout(this.commandTimeout);
      this.commandTimeout = null;
    }
  }

  constructor(
    sessionId: string,
    target: string,
    username: string,
    type: SessionType,
    client: Client,
    port: number = 22,
    mode: SessionMode = 'normal',
    timeoutMs: number = TIMEOUTS.DEFAULT_SESSION,
    shellType: ShellType = 'bash'
  ) {
    super();
    this.client = client;
    this.sessionTimeoutMs = timeoutMs;
    this.commandDelimiter = `___CMD_${Date.now()}_${Math.random().toString(36).substring(2, 11)}___`;
    this.shellType = shellType;
    this.shellFormatter = createShellFormatter(shellType);

    this.sessionInfo = {
      sessionId,
      target,
      username,
      type,
      mode,
      createdAt: new Date(),
      lastActivity: new Date(),
      port,
      workingDirectory: '~',
      environmentVars: new Map(),
      isActive: false,
      commandHistory: []
    };
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    return new Promise((resolve, reject) => {
      // Track whether the init promise has been settled. A shell close or
      // error event during the 1s startup window must reject initialize()
      // rather than letting the outer setTimeout resolve a dead session.
      // (Codex pre-push cycle 3 finding-4.)
      let initSettled = false;
      const settleResolve = (): void => {
        if (initSettled) return;
        initSettled = true;
        resolve();
      };
      const settleReject = (err: Error): void => {
        if (initSettled) return;
        initSettled = true;
        reject(err);
      };

      // OBS-003: propagate scenario run + session IDs to the Kali shell via
      // `env`. The Kali sshd_config must `AcceptEnv APTL_*` for these to
      // land (handled in containers/kali/Dockerfile). Build the PTY tee
      // up-front so every byte arriving on the shell stream is captured,
      // independent of which tool call eventually drains the buffer.
      // Capture the bound run id so a later harvest uses the trace id
      // that was active at session open, not whatever is active at close
      // time (codex pre-push cycle 3 finding-6).
      const shellEnv = aptlShellEnv(this.sessionInfo.sessionId);
      this.boundRunId = shellEnv.APTL_RUN_ID;
      this.ptyTee = createPtyTeeWriter(this.sessionInfo.sessionId);

      // #304: rebuild the remote-closed latch for THIS session's shell. A
      // fresh promise is needed once we have an actual stream so close() can
      // await the remote shutdown rather than returning the moment the local
      // cleanup completes.
      this.remoteClosed = new Promise((res) => { this.resolveRemoteClosed = res; });

      this.client.shell({ env: shellEnv }, (err, stream) => {
        if (err) {
          settleReject(new SSHError(`Failed to create shell: ${err.message}`, err));
          return;
        }

        this.shell = stream;
        this.sessionInfo.isActive = true;
        this.isInitialized = true;

        stream.on('data', (data: Buffer) => {
          this.ptyTee?.('out', data);
          this.handleShellOutput(data.toString());
        });

        stream.stderr.on('data', (data: Buffer) => {
          this.ptyTee?.('err', data);
          this.handleShellOutput(data.toString());
        });

        stream.on('close', () => {
          this.sessionInfo.isActive = false;
          // #304: signal the remote-close latch so any in-flight close()
          // call can return. Idempotent — Promise resolvers ignore second
          // calls.
          this.resolveRemoteClosed();
          if (!initSettled) {
            // Shell died before initialize() resolved — reject so the
            // caller does not receive a session that's already gone.
            this.cleanup();
            settleReject(new SSHError('Shell closed during initialization'));
            return;
          }
          this.cleanup();
          this.emitClosedIfVerified();
        });

        stream.on('error', (error: Error) => {
          if (!initSettled) {
            // Errors during init reject initialize() rather than emit an
            // 'error' event before the manager has had a chance to listen.
            settleReject(new SSHError(`Shell error during initialization: ${error.message}`, error));
            return;
          }
          this.emit('error', new SSHError(`Shell error: ${error.message}`, error));
        });

        this.startKeepAlive();
        this.resetSessionTimeout();

        setTimeout(settleResolve, 1000); // Shell startup delay
      });
    });
  }

  // Once-only, contract-gated 'closed' emission. Refuses to emit if cleanup
  // hasn't been verified, so manager listeners cannot record success on a
  // session whose postcondition failed. (Codex pre-push cycle 3 finding-2.)
  private emitClosedIfVerified(): void {
    if (this.closedEmitted) return;
    if (!this.cleanupVerified) return;
    this.closedEmitted = true;
    this.emit('closed');
  }

  async executeCommand(command: string, timeout: number = TIMEOUTS.DEFAULT_COMMAND, raw?: boolean): Promise<CommandResult> {
    require_(
      this.isInitialized && this.shell !== null && this.sessionInfo.isActive,
      'Session not initialized or inactive'
    );

    // Background sessions should return immediately after queuing
    if (this.sessionInfo.type === 'background') {
      const commandId = `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
      const request: CommandRequest = {
        id: commandId,
        command,
        resolve: () => {}, // No-op resolve for background
        reject: () => {}, // No-op reject for background
        timeout,
        raw: raw !== undefined ? raw : this.sessionInfo.mode === 'raw'
      };

      this.commandQueue.push(request);
      this.sessionInfo.commandHistory.push(command);
      this.sessionInfo.lastActivity = new Date();
      this.resetSessionTimeout();

      if (!this.currentCommand) {
        this.processNextCommand();
      }

      // Return immediately for background sessions
      return {
        stdout: `Command '${command}' queued in background session '${this.sessionInfo.sessionId}'`,
        stderr: '',
        code: 0,
        signal: null,
        // #282: even the immediate-return path carries effective mode so
        // observability sees the same signal as the eventual completion.
        mode: request.raw ? 'raw' : 'normal',
      };
    }

    // Interactive sessions wait for completion
    return new Promise((resolve, reject) => {
      const commandId = `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
      const request: CommandRequest = {
        id: commandId,
        command,
        resolve,
        reject,
        timeout,
        raw: raw !== undefined ? raw : this.sessionInfo.mode === 'raw'
      };

      this.commandQueue.push(request);
      this.sessionInfo.commandHistory.push(command);
      this.sessionInfo.lastActivity = new Date();
      this.resetSessionTimeout();

      if (!this.currentCommand) {
        this.processNextCommand();
      }
    });
  }

  private processNextCommand(): void {
    if (this.commandQueue.length === 0 || !this.shell) return;

    this.currentCommand = this.commandQueue.shift()!;
    this.outputData = '';
    this.clearCommandTimeout();

    if (this.currentCommand.raw) {
      // Raw mode: send command directly without wrapping
      this.shell.write(this.currentCommand.command + '\n');

      // For raw mode, we'll use a simpler timeout-based approach
      if (this.currentCommand.timeout) {
        const commandId = this.currentCommand.id;
        const timeoutDuration = this.currentCommand.timeout;
        this.commandTimeout = setTimeout(() => {
          if (this.currentCommand?.id === commandId) {
            // In raw mode, resolve with whatever output we've collected
            const output = this.outputData;
            this.commandTimeout = null;
            this.currentCommand!.resolve({
              stdout: output,
              stderr: '',
              code: 0, // Unknown in raw mode
              signal: null,
              mode: 'raw',
            });
            this.currentCommand = null;
            this.processNextCommand();
          }
        }, timeoutDuration);
      }
    } else {
      // Normal mode: use delimiter wrapping
      const startDelimiter = `${this.commandDelimiter}_START_${this.currentCommand.id}`;
      const endDelimiter = `${this.commandDelimiter}_END_${this.currentCommand.id}`;

      const wrappedCommand = this.shellFormatter.formatCommandWithDelimiters(
        this.currentCommand.command,
        startDelimiter,
        endDelimiter
      );

      this.shell.write(wrappedCommand + '\n');

      if (this.currentCommand.timeout) {
        const commandId = this.currentCommand.id;
        this.commandTimeout = setTimeout(() => {
          if (this.currentCommand?.id === commandId) {
            this.commandTimeout = null;
            this.currentCommand!.reject(new SSHError(`Command timeout: ${this.currentCommand!.command}`));
            this.currentCommand = null;
            this.processNextCommand();
          }
        }, this.currentCommand.timeout);
      }
    }
  }

  private handleShellOutput(data: string): void {
    if (this.sessionInfo.type === 'background') {
      this.outputBuffer.push(data);
      if (this.outputBuffer.length > BUFFER_LIMITS.MAX_SIZE) {
        this.outputBuffer = this.outputBuffer.slice(-BUFFER_LIMITS.TRIM_TO);
      }
    }

    if (this.currentCommand) {
      this.outputData += data;
      this.parseCommandOutput();
    }
  }

  private parseCommandOutput(): void {
    if (!this.currentCommand) return;

    // Skip parsing for raw mode commands
    if (this.currentCommand.raw) {
      // Raw mode output is handled by timeout in processNextCommand
      return;
    }

    // Strip carriage returns to normalize line endings before parsing
    const normalizedOutput = this.outputData.replace(/\r/g, '');

    const endDelimiter = `${this.commandDelimiter}_END_${this.currentCommand.id}`;
    const exitCode = this.shellFormatter.parseExitCode(normalizedOutput, endDelimiter);

    if (exitCode !== null) {
      const startPattern = `${this.commandDelimiter}_START_${this.currentCommand.id}`;
      const startIndex = normalizedOutput.indexOf(startPattern);
      const endPattern = `${endDelimiter}:${exitCode}`;
      const endIndex = normalizedOutput.indexOf(endPattern);

      if (startIndex !== -1 && endIndex !== -1) {
        const output = normalizedOutput.substring(
          startIndex + startPattern.length,
          endIndex
        ).trim();

        const lines = output.split('\n');
        if (lines[0] === '') lines.shift();
        if (lines[lines.length - 1] === '') lines.pop();

        // Filter out lines containing internal command delimiters or command echo
        const delimiter = this.commandDelimiter;
        const filteredLines = lines.filter(line => !line.includes(delimiter));

        const cleanOutput = filteredLines.join('\n');

        this.clearCommandTimeout();
        this.currentCommand.resolve({
          stdout: cleanOutput,
          stderr: '',
          code: exitCode,
          signal: null,
          mode: 'normal',
        });

        this.currentCommand = null;
        this.processNextCommand();
      }
    }
  }

  getSessionInfo(): SessionMetadata {
    return {
      ...this.sessionInfo,
      commandHistory: [...this.sessionInfo.commandHistory],
      environmentVars: new Map(this.sessionInfo.environmentVars)
    };
  }

  /**
   * OBS-003: the trace_id (`APTL_RUN_ID`) captured at session-open
   * time. Returned `undefined` if no scenario was active when the
   * session opened. The manager's harvest path passes this to
   * `harvestSession({ runId })` so a scenario rotation during a
   * long-running session does not redirect the harvest to a different
   * run dir (codex pre-push cycle 3 finding-6).
   */
  getBoundRunId(): string | undefined {
    return this.boundRunId;
  }

  /**
   * OBS-003 testing aid: resolve when the per-session PTY tee has
   * flushed every chunk handed to it so far (or it failed and was
   * logged). Production code does NOT call this — the tee is
   * fires-and-logs by design. Tests use it instead of a
   * `setTimeout` race (test-quality review cycle 1 finding-6).
   */
  async flushPtyTee(): Promise<void> {
    if (this.ptyTee) {
      await this.ptyTee.flush();
    }
  }

  /**
   * The shell type that was passed to the constructor (and that
   * `createShellFormatter` was called with). Exposed for tests that
   * assert the type round-trips through the session (test-quality
   * review cycle 1 finding-2/3/4 — vacuous assertions could not
   * have caught a regression that ignored the constructor arg).
   */
  getShellType(): ShellType {
    return this.shellType;
  }

  getBufferedOutput(lines?: number, clear: boolean = false): string[] {
    const result = lines ? this.outputBuffer.slice(-lines) : [...this.outputBuffer];
    if (clear) {
      this.outputBuffer = [];
    }
    return result;
  }

  private startKeepAlive(): void {
    this.keepAliveInterval = setInterval(() => {
      if (this.shell && this.sessionInfo.isActive && this.commandQueue.length === 0 && !this.currentCommand) {
        this.shell.write(this.shellFormatter.getKeepAliveCommand());
      }
    }, TIMEOUTS.KEEP_ALIVE_INTERVAL);
  }

  private resetSessionTimeout(): void {
    if (this.sessionTimeout) {
      clearTimeout(this.sessionTimeout);
    }

    this.sessionTimeout = setTimeout(() => {
      this.emit('timeout');
      // Timer-callback path: close() is async, so every failure path —
      // including the synchronous postcondition throw — surfaces as a
      // rejection on the returned promise. Catch that to keep timer
      // callbacks crash-safe under Node.
      void this.close().catch((err) => {
        console.error('[SSH] session timeout close failed:', err);
      });
    }, this.sessionTimeoutMs);
  }

  async close(): Promise<void> {
    this.doCleanup();
    if (this.shell) {
      this.shell.end();
    }
    // Run the postcondition before flipping cleanupVerified so a violation
    // cannot mark the session as cleanly torn down. If assertion throws,
    // cleanupVerified stays false; the manager catches the throw and routes
    // failure through its reject path. (Codex pre-push cycle 3 finding-2 +
    // finding-3.)
    this.assertCleanupInvariants();
    this.cleanupVerified = true;

    // #304 + codex review (class-finding): emitClosedIfVerified() does NOT
    // run yet. The 'closed' event's contract is "local cleanup verified AND
    // remote close observed or bounded timeout fired" — the manager's
    // session-map drop must not happen while the kali wrapper's EXIT trap
    // could still be flushing tcpdump / typescript. The stream.on('close')
    // handler's cleanup() will emit 'closed' synchronously if the remote
    // fires close during this await; we cover the timeout case explicitly
    // below. The closedEmitted latch keeps emission single-shot regardless
    // of which path wins.
    await new Promise<void>((res) => {
      let settled = false;
      const settle = (timedOut: boolean): void => {
        if (settled) return;
        settled = true;
        if (timedOut) {
          console.error(
            `[SSH] remote close timeout for session ${this.sessionInfo.sessionId}; ` +
              'kali-side capture may be partial. MCP-side captures remain authoritative.',
          );
        }
        clearTimeout(timer);
        res();
      };
      const timer = setTimeout(() => settle(true), TIMEOUTS.REMOTE_CLOSE_AWAIT);
      this.remoteClosed.then(() => settle(false));
    });

    // Now safe to signal 'closed' to the manager. If stream.on('close')
    // already ran cleanup() during the await, emitClosedIfVerified() is a
    // no-op via the closedEmitted latch. If we reached here via the
    // bounded timeout, this is the only emission path — the manager
    // releases the session id only after the wrapper's flush window has
    // either completed or expired.
    this.emitClosedIfVerified();
  }

  // Internal event-handler entry. Called from `stream.on('close')`; must not
  // propagate a contract violation because the EventEmitter would surface it
  // as an uncaught error and crash the Node process. A violation here LOGS
  // and leaves cleanupVerified=false so emitClosedIfVerified will not fire
  // for this path — the manager learns about the broken session via the
  // 'error' event we emit below (if a listener is attached), NOT 'closed'.
  private cleanup(): void {
    this.doCleanup();
    try {
      this.assertCleanupInvariants();
      this.cleanupVerified = true;
    } catch (err) {
      console.error('[SSH] cleanup invariant violation:', err);
      // Guard the 'error' emit with listenerCount: Node's EventEmitter throws
      // `Unhandled 'error' event` if 'error' is emitted with no listener,
      // which would defeat the whole point of this defensive catch. In
      // production the manager attaches an 'error' listener in createSession,
      // so the signal reaches its owner.
      if (this.listenerCount('error') > 0) {
        this.emit('error', err instanceof Error ? err : new SSHError(String(err)));
      }
    }
  }

  // Shared work — verbatim extraction of the prior cleanup() body. Stays a
  // pure state-mutation routine; the postcondition check lives in its own
  // method so callers can choose throw-vs-log per context.
  private doCleanup(): void {
    if (this.keepAliveInterval) {
      clearInterval(this.keepAliveInterval);
      this.keepAliveInterval = null;
    }

    if (this.sessionTimeout) {
      clearTimeout(this.sessionTimeout);
      this.sessionTimeout = null;
    }

    this.sessionInfo.isActive = false;

    this.clearCommandTimeout();

    if (this.currentCommand) {
      const current = this.currentCommand;
      this.currentCommand = null;
      current.reject(new SSHError('Session closed while command was in progress'));
    }

    const queued = this.commandQueue;
    this.commandQueue = [];
    for (const request of queued) {
      request.reject(new SSHError('Session closed while command was queued'));
    }
  }

  private assertCleanupInvariants(): void {
    ensure(this.sessionInfo.isActive === false, 'session still active after cleanup');
    ensure(this.keepAliveInterval === null, 'keepAliveInterval not cleared');
    ensure(this.sessionTimeout === null, 'sessionTimeout not cleared');
    ensure(this.commandTimeout === null, 'commandTimeout not cleared');
    ensure(this.currentCommand === null, 'currentCommand not cleared');
    ensure(this.commandQueue.length === 0, 'commandQueue not drained');
  }
}

export class SSHConnectionManager {
  private connections: Map<string, ConnectionInfo> = new Map();
  private sessions: Map<string, PersistentSession> = new Map();
  // In-flight createSession calls keyed by session id. Tracking the actual
  // promise (not just the id) lets disconnectAll quiesce by awaiting them
  // before sweeping; otherwise a reserved-but-incomplete create could
  // repopulate the sessions map after teardown returned successfully.
  // (Codex pre-push cycle 3 finding-1.)
  private readonly pendingSessions: Map<string, Promise<PersistentSession>> = new Map();
  // Joined in-flight connection creations keyed by `${user}@${host}:${port}`.
  // Concurrent callers requesting the same connection share one underlying
  // SSH client rather than racing to `connections.set`, which would orphan
  // every loser of the race.
  private readonly pendingConnections: Map<string, Promise<Client>> = new Map();

  /**
   * Execute a command on a target host via SSH.
   *
   * OBS-003 / ADR-033: when `sessionId` is supplied (or generated
   * internally as `exec-<ts>-<rand>` when absent), the one-shot
   * exec path now propagates `APTL_SESSION_ID` / `APTL_RUN_ID` /
   * `APTL_TRACE_ID` via SSH `env` and tees every byte read from
   * stdout/stderr into the same per-run JSONL the persistent
   * session path writes (codex pre-push cycle 1 finding-3). The
   * caller can read back the session id from the returned envelope
   * so it can trigger a per-exec capture harvest.
   */
  public async executeCommand(
    host: string,
    username: string,
    privateKeyPath: string,
    command: string,
    port: number = 22,
    timeout: number = TIMEOUTS.DEFAULT_COMMAND,
    options: { sessionId?: string } = {},
  ): Promise<CommandResult & { sessionId: string }> {
    const client = await this.getConnection(host, username, privateKeyPath, port);
    const sessionId =
      options.sessionId ??
      // crypto.randomBytes for the unique-id suffix (SonarCloud
      // hotspot ssh.ts:677 — Math.random isn't a CSPRNG). The id is
      // not security-sensitive (it's an experimental-record join
      // key), but the CSPRNG version is the same cost and removes
      // the hotspot.
      `exec-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const shellEnv = aptlShellEnv(sessionId);
    const ptyTee = createPtyTeeWriter(sessionId);

    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let hasTimedOut = false;

      const timeoutId = setTimeout(() => {
        hasTimedOut = true;
        reject(new SSHError(`Command timeout after ${timeout}ms: ${command}`));
      }, timeout);

      client.exec(command, { env: shellEnv }, (err, stream) => {
        if (err) {
          clearTimeout(timeoutId);
          reject(new SSHError(`Failed to execute command: ${err.message}`, err));
          return;
        }

        stream.on('close', (code: number | null, signal: string | null) => {
          clearTimeout(timeoutId);
          if (!hasTimedOut) {
            // One-shot exec has no session-level mode; the wrapping always
            // emits a real exit code so the effective mode is 'normal'.
            resolve({ stdout, stderr, code, signal, sessionId, mode: 'normal' });
          }
        });

        stream.on('data', (data: Buffer) => {
          ptyTee('out', data);
          stdout += data.toString();
        });

        stream.stderr.on('data', (data: Buffer) => {
          ptyTee('err', data);
          stderr += data.toString();
        });

        stream.on('error', (error: Error) => {
          clearTimeout(timeoutId);
          if (!hasTimedOut) {
            reject(new SSHError(`Stream error: ${error.message}`, error));
          }
        });
      });
    });
  }

  /**
   * Get or create an SSH connection to a host
   */
  private async getConnection(
    host: string,
    username: string,
    privateKeyPath: string,
    port: number = 22
  ): Promise<Client> {
    const connectionKey = `${username}@${host}:${port}`;
    console.error(`[SSH-CLIENT] getConnection called with key: ${connectionKey}`);

    if (this.connections.has(connectionKey)) {
      const connInfo = this.connections.get(connectionKey)!;
      if (connInfo.connected) {
        console.error(`[SSH-CLIENT] Reusing existing connection for: ${connectionKey}`);
        return connInfo.client;
      }
      // Connection is dead, remove it
      console.error(`[SSH-CLIENT] Removing dead connection for: ${connectionKey}`);
      this.connections.delete(connectionKey);
    }

    // Join an in-flight creation rather than racing to `connections.set`.
    const pending = this.pendingConnections.get(connectionKey);
    if (pending) {
      console.error(`[SSH-CLIENT] Joining in-flight connection for: ${connectionKey}`);
      return pending;
    }

    console.error(`[SSH-CLIENT] Creating new connection for: ${connectionKey}`);
    const creating = this.createConnection(host, username, privateKeyPath, port)
      .then(client => {
        this.connections.set(connectionKey, { client, connected: true });
        this.pendingConnections.delete(connectionKey);
        console.error(`[SSH-CLIENT] Connection cache now has ${this.connections.size} connections`);
        return client;
      })
      .catch(err => {
        this.pendingConnections.delete(connectionKey);
        throw err;
      });
    this.pendingConnections.set(connectionKey, creating);
    return creating;
  }

  /**
   * Create a new SSH connection
   */
  private async createConnection(
    host: string,
    username: string,
    privateKeyPath: string,
    port: number = 22
  ): Promise<Client> {
    let privateKey: Buffer;
    try {
      privateKey = await readFile(privateKeyPath);
    } catch (error) {
      throw new SSHError(
        `Failed to read SSH private key from ${privateKeyPath}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }

    const client = new Client();

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new SSHError('Connection timeout'));
      }, TIMEOUTS.KEEP_ALIVE_INTERVAL);

      client.on('ready', () => {
        clearTimeout(timeout);
        resolve(client);
      });

      client.on('error', (err) => {
        clearTimeout(timeout);
        reject(new SSHError(`Connection failed to ${host}:${port}: ${err.message}`, err));
      });

      client.on('close', () => {
        // Mark connection as disconnected
        const connectionKey = `${username}@${host}:${port}`;
        const connInfo = this.connections.get(connectionKey);
        if (connInfo) {
          connInfo.connected = false;
        }
      });

      client.connect({
        host,
        port,
        username,
        privateKey,
        timeout: SSH_CONFIG.READY_TIMEOUT,
        readyTimeout: SSH_CONFIG.READY_TIMEOUT,
        keepaliveInterval: SSH_CONFIG.KEEPALIVE_INTERVAL,
        keepaliveCountMax: SSH_CONFIG.KEEPALIVE_COUNT_MAX,
      });
    });
  }

  /**
   * Create a new persistent session
   */
  public async createSession(
    sessionId: string,
    target: string,
    username: string,
    type: SessionType,
    privateKeyPath: string,
    port: number = 22,
    mode: SessionMode = 'normal',
    timeoutMs: number = TIMEOUTS.DEFAULT_SESSION,
    shellType: ShellType = 'bash'
  ): Promise<PersistentSession> {
    // Reserve the id SYNCHRONOUSLY (before any await) so a concurrent
    // createSession with the same id cannot pass the precondition and
    // overwrite this entry between getConnection() and session.initialize().
    require_(
      !this.sessions.has(sessionId) && !this.pendingSessions.has(sessionId),
      `Session with ID '${sessionId}' already exists`
    );

    const creation = (async (): Promise<PersistentSession> => {
      const client = await this.getConnection(target, username, privateKeyPath, port);
      const session = new PersistentSession(sessionId, target, username, type, client, port, mode, timeoutMs, shellType);

      // Attach ownership-transfer listeners BEFORE the initialize() await so a
      // stream close/error during the startup delay is not missed. 'closed'
      // fires only after cleanup-and-postcondition both pass; 'error' fires
      // when cleanup detected a postcondition violation. 'timeout' is
      // informational — close() runs next from the timer callback and emits
      // 'closed' or 'error' itself. (Codex cycle 3 findings 3 + 4.)
      session.on('closed', () => {
        this.sessions.delete(sessionId);
      });
      session.on('error', (error) => {
        console.error(`[SSH] Session ${sessionId} error:`, error);
        this.sessions.delete(sessionId);
      });
      session.on('timeout', () => {
        console.error(`[SSH] Session ${sessionId} timed out`);
      });

      await session.initialize();
      this.sessions.set(sessionId, session);
      return session;
    })();

    this.pendingSessions.set(sessionId, creation);
    try {
      return await creation;
    } finally {
      this.pendingSessions.delete(sessionId);
    }
  }

  /**
   * Get an existing session by ID
   */
  public getSession(sessionId: string): PersistentSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * OBS-003: expose the trace id (`APTL_RUN_ID`) captured at
   * session-open time so the close-time harvest can pin the
   * docker-cp source path to that run id, not the ambient one
   * (codex pre-push cycle 3 finding-6).
   */
  public getSessionRunId(sessionId: string): string | undefined {
    return this.sessions.get(sessionId)?.getBoundRunId();
  }

  /**
   * List all active sessions
   */
  public listSessions(): SessionMetadata[] {
    return Array.from(this.sessions.values()).map(session => session.getSessionInfo());
  }

  /**
   * Close a specific session
   */
  public async closeSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return false;
    }

    // close() runs cleanup + postcondition synchronously (so in-flight /
    // queued command promises reject immediately), then awaits the remote
    // SSH channel close so the post-close harvest cannot race the kali
    // wrapper's EXIT trap (#304). A postcondition violation throws
    // synchronously and surfaces here as an awaited rejection; the catch
    // handles both shapes via the standard rejection path.
    try {
      await session.close();
      // 'closed' listener installed in createSession already removed the
      // session synchronously; this delete + ensure is a belt-and-braces
      // postcondition check from the manager-side.
      this.sessions.delete(sessionId);
      ensure(!this.sessions.has(sessionId), `closeSession(${sessionId}) left manager entry behind`);
      return true;
    } catch (err) {
      // Cleanup failed. Drop the broken session from the manager so subsequent
      // calls don't see it, then propagate so the MCP handler envelope reports
      // the failure to the caller.
      this.sessions.delete(sessionId);
      throw err;
    }
  }

  /**
   * Execute a command in a specific session
   */
  public async executeInSession(
    sessionId: string,
    command: string,
    timeout?: number,
    raw?: boolean
  ): Promise<CommandResult> {
    const session = this.sessions.get(sessionId);
    require_(session !== undefined, `Session '${sessionId}' not found`);

    return session.executeCommand(command, timeout, raw);
  }

  /**
   * Get buffered output from a background session
   */
  public getSessionOutput(sessionId: string, lines?: number, clear?: boolean): string[] {
    const session = this.sessions.get(sessionId);
    require_(session !== undefined, `Session '${sessionId}' not found`);

    return session.getBufferedOutput(lines, clear);
  }

  /**
   * Close all connections and sessions
   */
  public async disconnectAll(): Promise<void> {
    // Each teardown returns ok=true on clean shutdown OR ok=false carrying the
    // failure. We MUST NOT let a single failure short-circuit the whole sweep
    // (one stranded session would skip every subsequent close); use
    // allSettled-style per-target capture, force-clear the maps, then surface
    // every failure to the caller via the existing SSHError envelope so the
    // MCP handler can report a non-success result.
    type TeardownResult = { ok: true } | { ok: false; error: unknown };

    // Quiesce in-flight creates before snapshotting the established maps. A
    // createSession reserved its id but hasn't yet sessions.set() it; if the
    // sweep ran first, the established maps would be empty (passing the
    // ensure postcondition) and the pending create would repopulate after
    // shutdown returned. Same for pendingConnections. Wait for everything in
    // flight to settle so its result is either in the established map (which
    // this sweep then closes) or failed entirely. (Codex cycle 3 finding-1.)
    if (this.pendingSessions.size > 0 || this.pendingConnections.size > 0) {
      const pendingPromises: Array<Promise<unknown>> = [
        ...Array.from(this.pendingSessions.values()),
        ...Array.from(this.pendingConnections.values()),
      ];
      await Promise.allSettled(pendingPromises);
    }

    // Single teardown primitive shared by sessions and connections — both
    // race a close-call against an event-listener / timeout, capture the
    // per-target outcome, and propagate close failures via TeardownResult.
    const teardown = (
      doClose: () => void,
      emitter: EventEmitter,
      eventName: string,
    ): Promise<TeardownResult> => {
      return new Promise<TeardownResult>((resolve) => {
        let settled = false;
        const finish = (result: TeardownResult): void => {
          if (settled) return;
          settled = true;
          resolve(result);
        };

        const timeout = setTimeout(() => finish({ ok: true }), TIMEOUTS.SESSION_CLOSE);
        emitter.once(eventName, () => {
          clearTimeout(timeout);
          finish({ ok: true });
        });

        try {
          doClose();
        } catch (err) {
          clearTimeout(timeout);
          finish({ ok: false, error: err });
        }
      });
    };

    // Sessions: await close() directly (#304). close() resolves after the
    // remote SSH channel has actually closed or the bounded timeout fires,
    // so we no longer need the event-listener race against the SESSION_CLOSE
    // force-close timer. A throw from the synchronous postcondition stage
    // surfaces here as a rejection and is captured as TeardownResult.error.
    const sessionPromises: Array<Promise<TeardownResult>> = Array.from(this.sessions.values()).map(async (session) => {
      try {
        await session.close();
        return { ok: true as const };
      } catch (err) {
        return { ok: false as const, error: err };
      }
    });

    // #304 + codex review (class-finding): wait for every session's
    // close() promise to settle BEFORE tearing down the parent SSH
    // transport. Otherwise client.end() can begin while sessions are
    // still draining their channels — exactly the race close()
    // already closes per-session. The connections teardown happens in
    // a second phase below.
    const sessionResults = await Promise.all(sessionPromises);

    const connectionPromises: Array<Promise<TeardownResult>> = Array.from(this.connections.values()).map(connInfo => {
      if (!connInfo.connected) return Promise.resolve({ ok: true } as TeardownResult);
      return teardown(() => connInfo.client.end(), connInfo.client, 'close');
    });

    const connectionResults = await Promise.all(connectionPromises);
    const results = [...sessionResults, ...connectionResults];
    const failures = results.filter((r): r is { ok: false; error: unknown } => r.ok === false);

    this.sessions.clear();
    this.connections.clear();
    ensure(this.sessions.size === 0, 'disconnectAll left sessions behind');
    ensure(this.connections.size === 0, 'disconnectAll left connections behind');

    if (failures.length > 0) {
      // Map cleared so the manager is in a defined state, but the caller MUST
      // learn that one or more teardowns failed (otherwise a stranded command
      // promise inside a rejected close path looks like clean shutdown).
      const messages = failures.map(f =>
        f.error instanceof Error ? f.error.message : String(f.error)
      );
      const cause = failures[0].error instanceof Error ? failures[0].error : undefined;
      console.error('[SSH] disconnectAll teardown failure(s):', messages);
      throw new SSHError(
        `disconnectAll: ${failures.length} teardown failure(s): ${messages.join('; ')}`,
        cause
      );
    }
  }
}
