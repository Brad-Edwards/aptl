
import { Client } from 'ssh2';
import { readFile } from 'fs/promises';
import { EventEmitter } from 'events';
import { randomBytes } from 'node:crypto';
import { ShellType } from './shells.js';
import { createPtyTeeWriter } from './runs.js';
import {
  SSHError,
  require_,
  ensure,
  TIMEOUTS,
  SSH_CONFIG,
  redactCommand,
  aptlShellEnv,
  CommandResult,
  SessionType,
  SessionMode,
  SessionMetadata,
} from './ssh-contracts.js';
import { PersistentSession } from './ssh-session.js';

interface ConnectionInfo {
  client: Client;
  connected: boolean;
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
        reject(new SSHError(`Command timeout after ${timeout}ms: ${redactCommand(command)}`));
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
