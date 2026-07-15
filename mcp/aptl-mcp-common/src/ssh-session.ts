
import { Client, ClientChannel } from 'ssh2';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import { ShellFormatter, ShellType, createShellFormatter } from './shells.js';
import { createPtyTeeWriter } from './runs.js';
import {
  SSHError,
  require_,
  ensure,
  TIMEOUTS,
  BUFFER_LIMITS,
  redactCommand,
  aptlShellEnv,
  CommandResult,
  SessionType,
  SessionMetadata,
  CommandRequest,
  SessionConnectOptions,
} from './ssh-contracts.js';

export class PersistentSession extends EventEmitter {
  private shell: ClientChannel | null = null;
  private outputBuffer: string[] = [];
  private commandQueue: CommandRequest[] = [];
  private currentCommand: CommandRequest | null = null;
  private readonly sessionInfo: SessionMetadata;
  private readonly client: Client;
  private readonly commandDelimiter: string;
  private keepAliveInterval: NodeJS.Timeout | null = null;
  private sessionTimeout: NodeJS.Timeout | null = null;
  private commandTimeout: NodeJS.Timeout | null = null;
  private isInitialized = false;
  private outputData = '';
  private readonly shellFormatter: ShellFormatter;
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

  private readonly sessionTimeoutMs: number;

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
    options: SessionConnectOptions = {}
  ) {
    super();
    const {
      port = 22,
      mode = 'normal',
      timeoutMs = TIMEOUTS.DEFAULT_SESSION,
      shellType = 'bash'
    } = options;
    this.client = client;
    this.sessionTimeoutMs = timeoutMs;
    // crypto.randomBytes for the unique-id suffix (SonarCloud S2245 —
    // Math.random isn't a CSPRNG). The delimiter is not security-sensitive
    // (it only marks command boundaries in the shell stream), but the
    // CSPRNG version is the same cost and removes the finding.
    this.commandDelimiter = `___CMD_${Date.now()}_${randomBytes(4).toString('hex')}___`;
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
      // crypto.randomBytes for the unique-id suffix (SonarCloud S2245 —
      // Math.random isn't a CSPRNG). The command id is not
      // security-sensitive (it is an internal request-correlation key), but
      // the CSPRNG version is the same cost and removes the finding.
      const commandId = `${Date.now()}_${randomBytes(4).toString('hex')}`;
      const request: CommandRequest = {
        id: commandId,
        command,
        resolve: () => {}, // No-op resolve for background
        reject: () => {}, // No-op reject for background
        timeout,
        raw: raw ?? (this.sessionInfo.mode === 'raw')
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
      // crypto.randomBytes for the unique-id suffix (SonarCloud S2245 —
      // Math.random isn't a CSPRNG). The command id is not
      // security-sensitive (it is an internal request-correlation key), but
      // the CSPRNG version is the same cost and removes the finding.
      const commandId = `${Date.now()}_${randomBytes(4).toString('hex')}`;
      const request: CommandRequest = {
        id: commandId,
        command,
        resolve,
        reject,
        timeout,
        raw: raw ?? (this.sessionInfo.mode === 'raw')
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
            this.currentCommand.resolve({
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
          const current = this.currentCommand;
          if (current?.id === commandId) {
            this.commandTimeout = null;
            current.reject(new SSHError(`Command timeout: ${redactCommand(current.command)}`));
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
    const normalizedOutput = this.outputData.replaceAll('\r', '');

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
        if (lines.at(-1) === '') lines.pop();

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
      // Send a shell-level exit before EOF. A bare channel EOF can make sshd
      // tear down the ForceCommand process group before the Kali capture
      // wrapper's inner `script(1)` process flushes its transcript FIFO. All
      // supported shell types accept `exit`; stream.end preserves write order
      // and then half-closes the SSH channel so the wrapper can wait for its
      // capture client and exit cleanly.
      this.shell.end('exit\n');
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
