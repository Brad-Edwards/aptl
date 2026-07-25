import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('ssh2', () => ({
  Client: vi.fn(),
}));

import { PersistentSession, SSHConnectionManager, SSHError } from '../src/ssh.js';
import { ShellType } from '../src/shells.js';
import { EventEmitter } from 'events';

// Test our business logic, not the ssh2 library
describe('Session State Management', () => {
  it('should create session metadata correctly', () => {
    const mockClient = {} as any;
    const session = new PersistentSession('test-id', 'test-host', 'test-user', 'interactive', mockClient, { port: 2222, mode: 'normal', timeoutMs: 60000 });

    const info = session.getSessionInfo();
    expect(info.sessionId).toBe('test-id');
    expect(info.target).toBe('test-host');
    expect(info.username).toBe('test-user');
    expect(info.type).toBe('interactive');
    expect(info.mode).toBe('normal');
    expect(info.port).toBe(2222);
    expect(info.isActive).toBe(false); // Not initialized yet
    expect(info.commandHistory).toEqual([]);
  });

  it('should return immutable session info copies', () => {
    const mockClient = {} as any;
    const session = new PersistentSession('test', 'host', 'user', 'interactive', mockClient, { port: 22 });

    const info1 = session.getSessionInfo();
    const info2 = session.getSessionInfo();

    expect(info1).not.toBe(info2); // Different object instances
    expect(info1).toEqual(info2); // Same content

    // Mutating returned object shouldn't affect internal state
    info1.isActive = true;
    info1.commandHistory.push('fake command');

    const info3 = session.getSessionInfo();
    expect(info3.isActive).toBe(false); // Original state preserved
    expect(info3.commandHistory).toEqual([]); // Original state preserved
  });

  it('should track different session types and modes', () => {
    const mockClient = {} as any;

    const interactive = new PersistentSession('i', 'host', 'user', 'interactive', mockClient);
    const background = new PersistentSession('b', 'host', 'user', 'background', mockClient);
    const raw = new PersistentSession('r', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'raw' });

    expect(interactive.getSessionInfo().type).toBe('interactive');
    expect(interactive.getSessionInfo().mode).toBe('normal');

    expect(background.getSessionInfo().type).toBe('background');
    expect(background.getSessionInfo().mode).toBe('normal');

    expect(raw.getSessionInfo().type).toBe('interactive');
    expect(raw.getSessionInfo().mode).toBe('raw');
  });
});

describe('Session Manager State Logic', () => {
  let manager: SSHConnectionManager;

  beforeEach(() => {
    manager = new SSHConnectionManager();
  });

  it('should start with empty session list', () => {
    expect(manager.listSessions()).toEqual([]);
  });

  it('should return false for closing non-existent session', async () => {
    const result = await manager.closeSession('does-not-exist');
    expect(result).toBe(false);
  });

  it('should return undefined for non-existent session', () => {
    const session = manager.getSession('does-not-exist');
    expect(session).toBeUndefined();
  });

  it('should handle empty session output requests gracefully', () => {
    expect(() => {
      manager.getSessionOutput('non-existent');
    }).toThrow("Session 'non-existent' not found");
  });

  it('should handle empty session command requests gracefully', async () => {
    await expect(
      manager.executeInSession('non-existent', 'test command')
    ).rejects.toThrow("Session 'non-existent' not found");
  });
});

describe('Buffer Management Logic', () => {
  it('should handle buffer operations safely', () => {
    const mockClient = {} as any;
    const session = new PersistentSession('buffer-test', 'host', 'user', 'background', mockClient, { port: 22 });

    // Test empty buffer
    let buffer = session.getBufferedOutput();
    expect(buffer).toEqual([]);

    // Test with line limit on empty buffer
    buffer = session.getBufferedOutput(10);
    expect(buffer).toEqual([]);

    // Test clear on empty buffer
    buffer = session.getBufferedOutput(undefined, true);
    expect(buffer).toEqual([]);
  });

  it('should keep newest data when buffer overflows', () => {
    const mockClient = {} as any;
    const session = new PersistentSession('overflow-test', 'host', 'user', 'background', mockClient, { port: 22 });

    // Drive the real handleShellOutput code path — NOT an inline replica.
    // BUFFER_LIMITS.MAX_SIZE=10000, TRIM_TO=5000 (ssh.ts). Push 12000
    // entries through handleShellOutput; the first trim happens after the
    // 10001st push (length becomes 5000), then 1999 more pushes bring the
    // final length to 6999, with the last 5000 newest entries being
    // `line 7000` through `line 11999` minus the discarded earlier entries.
    // Actually the trim resets to 5000 then continues; final length is
    // 5000 + (12000 - 10001) = 6999. Let me derive the kept window:
    //   - After push #10001: length=10001 > 10000 → slice(-5000) → length=5000
    //     keeps last 5000 of indices 5001..10000, i.e. `line 5001`..`line 10000`.
    //   - After push #12000 (1999 more pushes): length=6999, keeps
    //     `line 5001`..`line 10000` PLUS `line 10001`..`line 11999`,
    //     total 6999 entries ending with `line 11999`.
    // The contract this test pins: handleShellOutput's overflow detection
    // actually fires AND drops the oldest entries.
    for (let i = 0; i < 12000; i++) {
      (session as any).handleShellOutput(`line ${i}`);
    }

    const buffer = session.getBufferedOutput();
    expect(buffer.length).toBeLessThanOrEqual(10000);
    expect(buffer.length).toBeGreaterThanOrEqual(5000);
    // Earliest entry that survived the most recent trim. After the trim at
    // push #10001 (length 10001→5000), the oldest survivor is `line 5001`.
    // No further trim happens because pushes #10002..#12000 (1999 more)
    // only bring length to 6999, still under MAX_SIZE.
    expect(buffer[0]).toBe('line 5001');
    expect(buffer[buffer.length - 1]).toBe('line 11999');
    // The earliest entries are gone — proof that overflow trimming ran.
    expect(buffer).not.toContain('line 0');
    expect(buffer).not.toContain('line 5000');
  });
});

describe('Connection Key Generation Logic', () => {
  it('getConnection creates separate cache entries for distinct (user, host, port) tuples', async () => {
    // Pre-existing test slot was vacuous (asserted an empty manager).
    // Replaced with a real distinct-key test: stub createConnection to
    // count calls, then verify each unique tuple produces a separate cache
    // entry and a separate createConnection invocation. The companion
    // dedup test below ('getConnection deduplicates concurrent callers
    // for the same connection key') covers the equal-tuple half — the two
    // together pin both halves of the uniqueness contract.
    const manager = new SSHConnectionManager();
    const clients: Array<{ key: string; client: Client }> = [];
    (manager as any).createConnection = vi.fn(async (host: string, user: string, _key: string, port: number) => {
      const client = { tag: `${user}@${host}:${port}` } as unknown as Client;
      clients.push({ key: `${user}@${host}:${port}`, client });
      return client;
    });

    // Each tuple varies one dimension: host, port, user.
    const c1 = await (manager as any).getConnection('h1', 'u', '/k', 22);
    const c2 = await (manager as any).getConnection('h2', 'u', '/k', 22); // different host
    const c3 = await (manager as any).getConnection('h1', 'u', '/k', 23); // different port
    const c4 = await (manager as any).getConnection('h1', 'u2', '/k', 22); // different user
    // Same tuple as c1 — must reuse, not create.
    const c5 = await (manager as any).getConnection('h1', 'u', '/k', 22);

    // Four distinct clients, fifth reuses the first.
    expect(c1).not.toBe(c2);
    expect(c1).not.toBe(c3);
    expect(c1).not.toBe(c4);
    expect(c2).not.toBe(c3);
    expect(c2).not.toBe(c4);
    expect(c3).not.toBe(c4);
    expect(c5).toBe(c1);

    // Exactly 4 createConnection invocations for 4 distinct tuples.
    expect(clients.length).toBe(4);
    // Cache holds one entry per distinct tuple.
    expect((manager as any).connections.size).toBe(4);
    expect((manager as any).connections.has('u@h1:22')).toBe(true);
    expect((manager as any).connections.has('u@h2:22')).toBe(true);
    expect((manager as any).connections.has('u@h1:23')).toBe(true);
    expect((manager as any).connections.has('u2@h1:22')).toBe(true);
  });
});

describe('Shell Type Support', () => {
  it('should create sessions with default bash shell', () => {
    const mockClient = {} as any;
    const session = new PersistentSession('test-id', 'test-host', 'test-user', 'interactive', mockClient, { port: 22 });

    // Asserts the shell-type round-trips, not just that the session
    // exists (test-quality review cycle 1 finding-2). The previous
    // `expect(info).toBeDefined()` could not have caught a regression
    // that silently dropped the shellType default.
    expect(session.getShellType()).toBe('bash');
  });

  // Test-quality review cycle 1 T-004: split the previous forEach loop
  // into one named test per shell type so a regression affecting only
  // one type points at that type in the failure output, not at an
  // anonymous loop iteration.
  it.each<ShellType>(['bash', 'sh', 'powershell', 'cmd'])(
    'should create session with %s shell type',
    (shellType) => {
      const mockClient = {} as any;
      const session = new PersistentSession(`test-${shellType}`, 'test-host', 'test-user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 60000, shellType });

      const info = session.getSessionInfo();
      expect(info.sessionId).toBe(`test-${shellType}`);
      // Asserts the constructor-supplied shellType is stored — without
      // this, a regression that discarded the parameter would still
      // produce a passing test (test-quality review cycle 1 finding-3).
      expect(session.getShellType()).toBe(shellType);
    },
  );

  it('should track shell type through session lifecycle', async () => {
    // Test-quality review cycle 1 T-003: PR #304 made
    // PersistentSession.close() async. The previous unawaited
    // close() left a 3-second remote-close-await timer hanging
    // after the test returned. Use a real EventEmitter for the
    // stream so we can emit 'close' deterministically and await
    // the close promise cleanly.
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(() => mockStream.emit('close')),
        stderr: new EventEmitter(),
      });
      const mockClient = {
        shell: vi.fn((_opts: any, callback: any) => {
          callback(null, mockStream);
          return mockStream;
        })
      } as any;

      const powershellSession = new PersistentSession('ps-test', 'windows-host', 'Administrator', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 60000, shellType: 'powershell' });

      const initP = powershellSession.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      const info = powershellSession.getSessionInfo();
      expect(info.sessionId).toBe('ps-test');
      expect(info.target).toBe('windows-host');
      expect(info.username).toBe('Administrator');
      // The shellType must survive initialize() — without this
      // assertion, a regression where initialize() silently switched
      // back to bash would still pass (test-quality review cycle 1
      // finding-4).
      expect(powershellSession.getShellType()).toBe('powershell');

      await powershellSession.close();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('OBS-003: SendEnv + continuous PTY tee', () => {
  let tmp = '';

  beforeEach(() => {
    vi.useFakeTimers();
    const { mkdtempSync } = require('node:fs');
    const { tmpdir } = require('node:os');
    const { join } = require('node:path');
    tmp = mkdtempSync(join(tmpdir(), 'aptl-ssh-obs003-'));
    process.env.APTL_STATE_DIR = tmp;
  });

  afterEach(() => {
    vi.useRealTimers();
    const { rmSync } = require('node:fs');
    rmSync(tmp, { recursive: true, force: true });
    delete process.env.APTL_STATE_DIR;
  });

  it('passes APTL_SESSION_ID + APTL_RUN_ID + APTL_TRACE_ID via shell({env}) when scenario active', async () => {
    const { writeFileSync } = require('node:fs');
    const { join } = require('node:path');
    const tid = 'a'.repeat(32);
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ trace_id: tid, span_id: 'b'.repeat(16), trace_flags: '01' }),
    );

    const shellStream = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    const shellMock = vi.fn((_opts: any, cb: any) => cb(null, shellStream));
    const mockClient = { shell: shellMock } as any;

    const session = new PersistentSession('sess-obs003-1', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });

    const init = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await init;

    expect(shellMock).toHaveBeenCalledTimes(1);
    const opts = shellMock.mock.calls[0][0];
    expect(opts.env).toMatchObject({
      APTL_SESSION_ID: 'sess-obs003-1',
      APTL_RUN_ID: tid,
      APTL_TRACE_ID: tid,
    });

    session.close();
  });

  it('passes only APTL_SESSION_ID when no scenario context is active', async () => {
    const shellStream = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    const shellMock = vi.fn((_opts: any, cb: any) => cb(null, shellStream));
    const mockClient = { shell: shellMock } as any;

    const session = new PersistentSession(
      'sess-no-scenario', 'host', 'user', 'interactive', mockClient,
    );

    const init = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await init;

    const opts = shellMock.mock.calls[0][0];
    expect(opts.env).toEqual({ APTL_SESSION_ID: 'sess-no-scenario' });

    session.close();
  });

  it('tees every byte from stdout AND stderr into per-session JSONL', async () => {
    const { writeFileSync, readFileSync, existsSync } = require('node:fs');
    const { join } = require('node:path');
    const tid = 'c'.repeat(32);
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ trace_id: tid, span_id: 'd'.repeat(16) }),
    );

    const shellStream = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    const shellMock = vi.fn((_opts: any, cb: any) => cb(null, shellStream));
    const mockClient = { shell: shellMock } as any;

    const session = new PersistentSession('sess-tee-1', 'host', 'user', 'background', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });

    const init = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await init;

    // Emit a few chunks across both streams.
    shellStream.emit('data', Buffer.from('first chunk\n'));
    shellStream.stderr.emit('data', Buffer.from('warning text\n'));
    shellStream.emit('data', Buffer.from('second chunk\n'));

    // Let the async tee writer flush. Use the writer's own drain
    // (test-quality review cycle 1 finding-6) — a fixed setTimeout
    // races the actual write under CI load.
    vi.useRealTimers();
    await session.flushPtyTee();

    const file = join(tmp, 'runs', tid, 'mcp-side', 'sessions', 'sess-tee-1.jsonl');
    expect(existsSync(file)).toBe(true);
    const lines = readFileSync(file, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(3);
    const r0 = JSON.parse(lines[0]);
    expect(r0.dir).toBe('out');
    expect(Buffer.from(r0.b64, 'base64').toString()).toBe('first chunk\n');
    const r1 = JSON.parse(lines[1]);
    expect(r1.dir).toBe('err');
    expect(Buffer.from(r1.b64, 'base64').toString()).toBe('warning text\n');
    const r2 = JSON.parse(lines[2]);
    expect(r2.dir).toBe('out');
    expect(Buffer.from(r2.b64, 'base64').toString()).toBe('second chunk\n');

    session.close();
  });
});

describe('Session Cleanup and Timeout Handling', () => {
  let mockStream: EventEmitter & { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn>; stderr: EventEmitter };
  let mockClient: any;
  let session: PersistentSession;

  beforeEach(async () => {
    vi.useFakeTimers();

    mockStream = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });

    mockClient = {
      shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)),
    };

    session = new PersistentSession('cleanup-test', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });

    // initialize() has a setTimeout(resolve, 1000) that won't fire
    // under fake timers unless we advance concurrently
    const initPromise = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initPromise;
  });

  afterEach(() => {
    session.close();
    vi.useRealTimers();
  });

  it('cleanup rejects in-flight command', async () => {
    const commandPromise = session.executeCommand('sleep 999', 60000);

    // Command is now in-flight; close the session
    session.close();

    await expect(commandPromise).rejects.toThrow('Session closed while command was in progress');
    await expect(commandPromise).rejects.toBeInstanceOf(SSHError);
  });

  it('cleanup rejects queued commands', async () => {
    // Queue three commands — first becomes current, rest are queued
    const p1 = session.executeCommand('cmd1', 60000);
    const p2 = session.executeCommand('cmd2', 60000);
    const p3 = session.executeCommand('cmd3', 60000);

    session.close();

    await expect(p1).rejects.toThrow('Session closed while command was in progress');
    await expect(p2).rejects.toThrow('Session closed while command was queued');
    await expect(p3).rejects.toThrow('Session closed while command was queued');
  });

  it('redacts embedded credentials in the command-timeout rejection (sec-02)', async () => {
    // A timed-out command's SSHError can reach stderr ahead of the MCP
    // serialization boundary's redaction; the message must not leak the
    // password (ARCH-386-08 / sec-02). Attach the catch handler before
    // advancing the fake timer so the rejection is never momentarily
    // unhandled when the timeout fires.
    const errP = session
      .executeCommand('hydra -p hunter2 ssh://target', 5000)
      .catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5000);

    const err = (await errP) as SSHError;
    expect(err).toBeInstanceOf(SSHError);
    expect(err.message).toContain('Command timeout:');
    expect(err.message).toContain('[REDACTED]');
    expect(err.message).not.toContain('hunter2');

    // A credential-free command stays fully readable for debugging.
    const benignP = session
      .executeCommand('ls -la /tmp', 5000)
      .catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5000);
    const benignErr = (await benignP) as SSHError;
    expect(benignErr.message).toBe('Command timeout: ls -la /tmp');
  });

  it('per-command timeout cleared on success', async () => {
    const commandPromise = session.executeCommand('echo hello', 5000);

    // Simulate the shell producing delimiter-wrapped output
    const delimiter = (session as any).commandDelimiter;
    const cmdId = (session as any).currentCommand.id;
    const startMarker = `${delimiter}_START_${cmdId}`;
    const endMarker = `${delimiter}_END_${cmdId}`;

    mockStream.emit('data', Buffer.from(`${startMarker}\nhello\n${endMarker}:0\n`));

    const result = await commandPromise;
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('hello');

    // Advance past the 5000ms command timeout — should cause no side effects
    await vi.advanceTimersByTimeAsync(6000);

    // Session is still active and functional
    expect(session.getSessionInfo().isActive).toBe(true);
  });

  it('per-command timeout cleared on cleanup', async () => {
    const commandPromise = session.executeCommand('slow-cmd', 5000);

    // Close before timeout fires
    session.close();

    // Should reject with session-closed, not timeout
    await expect(commandPromise).rejects.toThrow('Session closed while command was in progress');

    // Advance past the timeout — should be a no-op
    await vi.advanceTimersByTimeAsync(6000);
  });

  it('cleanup is idempotent', async () => {
    const commandPromise = session.executeCommand('cmd', 60000);

    // First cleanup via close()
    session.close();

    await expect(commandPromise).rejects.toThrow('Session closed while command was in progress');

    // Second cleanup via the shell 'close' event (simulates shell.end() triggering close)
    mockStream.emit('close');

    // No additional errors or throws — the second cleanup is a no-op
    expect(session.getSessionInfo().isActive).toBe(false);
  });

  it('cleanup with nothing pending is a no-op', () => {
    // No commands queued or in flight
    expect(() => session.close()).not.toThrow();
    expect(session.getSessionInfo().isActive).toBe(false);
  });
});

describe('Contract guards (preconditions)', () => {
  it('executeCommand on uninitialized session throws SSHError before any shell access', async () => {
    const mockClient = { shell: vi.fn() } as any;
    const session = new PersistentSession('pre-uninit', 'host', 'user', 'interactive', mockClient, { port: 22 });

    // Two assertions: instance type + message substring. If the precondition
    // failed to fire, `this.shell` is still null and executeCommand would
    // throw a TypeError on `this.shell.write(...)` — that would fail the
    // `toBeInstanceOf(SSHError)` check, so this DOES verify "no shell
    // access" indirectly without needing a separate write-spy.
    await expect(session.executeCommand('ls', 1000)).rejects.toBeInstanceOf(SSHError);
    await expect(session.executeCommand('ls', 1000)).rejects.toThrow('Session not initialized or inactive');
  });

  it('executeCommand after close throws SSHError without writing to the shell', async () => {
    vi.useFakeTimers();
    try {
      // Spy-backed write so we can verify the precondition fires before the
      // executeCommand body ever reaches `this.shell.write(...)` — the
      // shell EXISTS here (init ran) but isActive is false, so a missing
      // precondition would otherwise let a write through.
      const writeSpy = vi.fn();
      const mockStream = Object.assign(new EventEmitter(), {
        write: writeSpy,
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('pre-closed', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initPromise = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initPromise;

      // Init may have written a keep-alive heartbeat; baseline the call count
      // BEFORE close() so the post-close assertion measures only the
      // executeCommand path. (Actually startKeepAlive only writes on
      // interval ticks; advancing 1s shouldn't trigger any. Reset anyway
      // to be robust against future changes to keep-alive timing.)
      writeSpy.mockClear();

      session.close();

      await expect(session.executeCommand('ls', 1000)).rejects.toBeInstanceOf(SSHError);
      await expect(session.executeCommand('ls', 1000)).rejects.toThrow('Session not initialized or inactive');
      // Precondition fired before any shell.write. close() itself does NOT
      // write to the shell (shell.end is via stream.end, not stream.write),
      // so the only way writeSpy would be called is if the precondition
      // leaked and executeCommand entered processNextCommand.
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('createSession refuses a duplicate session id without mutating manager state', async () => {
    const manager = new SSHConnectionManager();
    // Seed the manager's internal sessions map directly so we exercise createSession's
    // duplicate-id check in isolation from getConnection / shell wiring.
    const fakeSession = {} as PersistentSession;
    (manager as any).sessions.set('dup-id', fakeSession);

    await expect(
      manager.createSession('dup-id', 'host', 'user', 'interactive', '/tmp/key')
    ).rejects.toBeInstanceOf(SSHError);
    await expect(
      manager.createSession('dup-id', 'host', 'user', 'interactive', '/tmp/key')
    ).rejects.toThrow("Session with ID 'dup-id' already exists");

    // The original entry is untouched — duplicate create did not overwrite it.
    expect((manager as any).sessions.get('dup-id')).toBe(fakeSession);
    expect((manager as any).sessions.size).toBe(1);
  });

  it('executeInSession throws SSHError instance, not just message', async () => {
    const manager = new SSHConnectionManager();
    await expect(
      manager.executeInSession('ghost', 'echo hi')
    ).rejects.toBeInstanceOf(SSHError);
  });

  it('getSessionOutput throws SSHError instance, not just message', () => {
    const manager = new SSHConnectionManager();
    expect(() => manager.getSessionOutput('ghost')).toThrow(SSHError);
  });
});

describe('Contract guards (postconditions)', () => {
  let mockStream: EventEmitter & { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn>; stderr: EventEmitter };
  let mockClient: any;
  let session: PersistentSession;

  beforeEach(async () => {
    vi.useFakeTimers();
    mockStream = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) };
    session = new PersistentSession('post-test', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
    const initPromise = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initPromise;
  });

  afterEach(() => {
    try { session.close(); } catch { /* ignore — already closed by the test */ }
    vi.useRealTimers();
  });

  it('close() on idle session leaves the session fully torn down', () => {
    session.close();

    expect(session.getSessionInfo().isActive).toBe(false);
    expect((session as any).keepAliveInterval).toBeNull();
    expect((session as any).sessionTimeout).toBeNull();
    expect((session as any).commandTimeout).toBeNull();
    expect((session as any).currentCommand).toBeNull();
    expect((session as any).commandQueue).toEqual([]);
  });

  it('close() on busy session leaves session fully torn down and rejects every pending promise exactly once', () => {
    // Use spy-backed CommandRequest reject functions to pin the exact-once
    // contract — Promises ignore subsequent reject() calls, so an awaited
    // `.rejects` matcher only proves rejection happened at least once.
    const rejectCurrent = vi.fn();
    const rejectQ1 = vi.fn();
    const rejectQ2 = vi.fn();
    const resolveAll = vi.fn();

    (session as any).currentCommand = {
      id: 'current',
      command: 'in-flight',
      resolve: resolveAll,
      reject: rejectCurrent,
    };
    (session as any).commandQueue = [
      { id: 'q1', command: 'a', resolve: resolveAll, reject: rejectQ1 },
      { id: 'q2', command: 'b', resolve: resolveAll, reject: rejectQ2 },
    ];

    session.close();

    expect(rejectCurrent).toHaveBeenCalledTimes(1);
    expect(rejectQ1).toHaveBeenCalledTimes(1);
    expect(rejectQ2).toHaveBeenCalledTimes(1);
    expect(rejectCurrent.mock.calls[0][0]).toBeInstanceOf(SSHError);
    expect(rejectCurrent.mock.calls[0][0].message).toBe('Session closed while command was in progress');
    expect(rejectQ1.mock.calls[0][0]).toBeInstanceOf(SSHError);
    expect(rejectQ1.mock.calls[0][0].message).toBe('Session closed while command was queued');
    expect(rejectQ2.mock.calls[0][0]).toBeInstanceOf(SSHError);
    expect(rejectQ2.mock.calls[0][0].message).toBe('Session closed while command was queued');
    expect(resolveAll).not.toHaveBeenCalled();

    expect(session.getSessionInfo().isActive).toBe(false);
    expect((session as any).keepAliveInterval).toBeNull();
    expect((session as any).sessionTimeout).toBeNull();
    expect((session as any).commandTimeout).toBeNull();
    expect((session as any).currentCommand).toBeNull();
    expect((session as any).commandQueue.length).toBe(0);
  });

  it('assertCleanupInvariants() throws [contract] SSHError when state is intentionally corrupted', () => {
    // Provoke the postcondition: simulate a broken cleanup that left state behind.
    // This guards the assertion itself — a future refactor that drops a clear step
    // must be caught by the postcondition check, not slip through silently.
    (session as any).doCleanup();
    (session as any).currentCommand = { id: 'phantom', command: 'x', resolve: () => {}, reject: () => {} };

    expect(() => (session as any).assertCleanupInvariants())
      .toThrow(/\[contract\]/);
    expect(() => (session as any).assertCleanupInvariants())
      .toThrow(SSHError);
  });

  it('event-handler cleanup() swallows postcondition violations and logs', () => {
    // Verify the defensive try/catch in cleanup() — NOT the invariant itself.
    // We stub assertCleanupInvariants() to always throw so we can prove the
    // event-handler entry point catches it; doCleanup() would otherwise repair
    // any forced-corruption state before the check runs.
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const original = (session as any).assertCleanupInvariants;
    (session as any).assertCleanupInvariants = function () {
      throw new SSHError('[contract] simulated violation');
    };
    try {
      expect(() => (session as any).cleanup()).not.toThrow();

      const matched = errorSpy.mock.calls.some(call =>
        typeof call[0] === 'string' && call[0].includes('[SSH] cleanup invariant violation')
      );
      expect(matched).toBe(true);
    } finally {
      (session as any).assertCleanupInvariants = original;
      errorSpy.mockRestore();
    }
  });

  it('timer-callback close path swallows postcondition rejections and logs', async () => {
    // Same defensive contract for the resetSessionTimeout timer callback — an
    // uncaught rejection from setTimeout crashes Node. After #304, close() is
    // async so failures always surface as promise rejections; the timer
    // callback's `void this.close().catch(...)` swallows them. Stub close to
    // return a rejecting promise and verify the catch handler logs.
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalClose = session.close.bind(session);
    session.close = async () => {
      throw new SSHError('[contract] simulated close failure');
    };
    try {
      // Advance the timer to fire the session-timeout callback.
      // sessionTimeoutMs is 600000 (set in beforeEach).
      await vi.advanceTimersByTimeAsync(600000);

      const matched = errorSpy.mock.calls.some(call =>
        typeof call[0] === 'string' && call[0].includes('[SSH] session timeout close failed')
      );
      expect(matched).toBe(true);
    } finally {
      session.close = originalClose;
      errorSpy.mockRestore();
    }
  });
});

describe('Manager-level postconditions', () => {
  it('closeSession(id) removes id from manager when resolving true', async () => {
    vi.useFakeTimers();
    try {
      const manager = new SSHConnectionManager();
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(() => mockStream.emit('close')),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('mgr-close', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initPromise = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initPromise;
      (manager as any).sessions.set('mgr-close', session);
      session.on('closed', () => (manager as any).sessions.delete('mgr-close'));

      const result = await manager.closeSession('mgr-close');
      expect(result).toBe(true);
      expect(manager.getSession('mgr-close')).toBeUndefined();
      expect(manager.listSessions()).toEqual([]);
      expect((manager as any).sessions.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('disconnectAll() empties both the sessions map and the connections map', async () => {
    vi.useFakeTimers();
    try {
      const manager = new SSHConnectionManager();

      const stream1 = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(() => stream1.emit('close')),
        stderr: new EventEmitter(),
      });
      const stream2 = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(() => stream2.emit('close')),
        stderr: new EventEmitter(),
      });
      const client1 = Object.assign(new EventEmitter(), {
        shell: vi.fn((_opts: any, cb: any) => cb(null,stream1)),
        end: vi.fn(() => client1.emit('close')),
      });
      const client2 = Object.assign(new EventEmitter(), {
        shell: vi.fn((_opts: any, cb: any) => cb(null,stream2)),
        end: vi.fn(() => client2.emit('close')),
      });
      const s1 = new PersistentSession('s1', 'h', 'u', 'interactive', client1 as any, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const s2 = new PersistentSession('s2', 'h', 'u', 'interactive', client2 as any, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP1 = s1.initialize();
      const initP2 = s2.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await Promise.all([initP1, initP2]);
      (manager as any).sessions.set('s1', s1);
      (manager as any).sessions.set('s2', s2);
      (manager as any).connections.set('u@h:22', { client: client1, connected: true });
      (manager as any).connections.set('u@h:23', { client: client2, connected: true });

      const allDone = manager.disconnectAll();
      // disconnectAll() awaits 'closed' events and 'close' events; the mocked
      // stream.end and client.end fire those synchronously above, so the promise
      // resolves on the next microtask.
      await vi.runAllTimersAsync();
      await allDone;

      expect((manager as any).sessions.size).toBe(0);
      expect((manager as any).connections.size).toBe(0);
      expect(manager.listSessions()).toEqual([]);
      // Both sessions must actually be closed, not just removed
      // from the manager map (test-quality cycle 2 finding-3 — a
      // regression that just cleared the map would otherwise leave
      // active sessions leaking keep-alive timers + SSH channels).
      expect(s1.getSessionInfo().isActive).toBe(false);
      expect(s2.getSessionInfo().isActive).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('disconnectAll() propagates SSHError to the caller when a teardown contract fails', async () => {
    // Codex finding (cycle 1): the prior implementation force-cleared maps
    // and the postcondition then passed vacuously even when session.close()
    // threw a [contract] SSHError, hiding a stranded command path. The
    // current implementation MUST surface that failure through the existing
    // SSHError envelope so the MCP handler reports a non-success result.
    vi.useFakeTimers();
    try {
      const manager = new SSHConnectionManager();
      const stream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(() => stream.emit('close')),
        stderr: new EventEmitter(),
      });
      const client = Object.assign(new EventEmitter(), {
        shell: vi.fn((_opts: any, cb: any) => cb(null,stream)),
        end: vi.fn(() => client.emit('close')),
      });
      const sessionA = new PersistentSession('a', 'h', 'u', 'interactive', client as any, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = sessionA.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      // Inject the contract failure: stub close() on this session to throw.
      sessionA.close = () => { throw new SSHError('[contract] simulated cleanup violation'); };

      (manager as any).sessions.set('a', sessionA);
      (manager as any).connections.set('u@h:22', { client, connected: true });

      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      try {
        // disconnectAll's per-target promises resolve synchronously here:
        // the stubbed close() throws sync, and the mocked client.end emits
        // 'close' sync. Microtask drain is enough; vi.runAllTimersAsync
        // would chase the keep-alive setInterval forever and abort.
        const promise = manager.disconnectAll();
        await expect(promise).rejects.toBeInstanceOf(SSHError);
        await expect(promise).rejects.toThrow(/teardown failure/);

        // Maps are still cleared so the manager is in a defined state.
        expect((manager as any).sessions.size).toBe(0);
        expect((manager as any).connections.size).toBe(0);
        // The failure was logged for operability.
        const matched = errorSpy.mock.calls.some(call =>
          typeof call[0] === 'string' && call[0].includes('[SSH] disconnectAll teardown failure')
        );
        expect(matched).toBe(true);
      } finally {
        errorSpy.mockRestore();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('closeSession() rejects with the contract SSHError when session.close() throws', async () => {
    // Codex finding (cycle 1): the prior implementation had `ensure()` calls
    // inside a setTimeout callback and an EventEmitter `'closed'` handler,
    // both of which would surface a contract violation as an uncaught
    // exception. The fix routes the failure through the Promise's reject so
    // the MCP handler envelope catches it.
    vi.useFakeTimers();
    try {
      const manager = new SSHConnectionManager();
      const stream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const client = Object.assign(new EventEmitter(), {
        shell: vi.fn((_opts: any, cb: any) => cb(null,stream)),
      });
      const sessionA = new PersistentSession('a', 'h', 'u', 'interactive', client as any, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = sessionA.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      sessionA.close = () => { throw new SSHError('[contract] simulated cleanup violation'); };
      (manager as any).sessions.set('a', sessionA);

      // closeSession's stubbed close() throws sync inside the Promise
      // executor, hitting `fail(err)` which rejects on the next microtask.
      // Same hazard as the disconnectAll test — runAllTimersAsync chases
      // the keep-alive setInterval forever and aborts.
      const promise = manager.closeSession('a');
      await expect(promise).rejects.toBeInstanceOf(SSHError);
      await expect(promise).rejects.toThrow(/simulated cleanup violation/);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Contract guards (event ordering & concurrency)', () => {
  it("close() does NOT emit 'closed' when assertCleanupInvariants throws", async () => {
    // Codex cycle-2 finding: prior implementation emitted 'closed' from
    // stream.on('close') inside shell.end(), BEFORE close()'s postcondition
    // ran. A manager listener would resolve success and a later contract
    // violation in close() would be silently swallowed. Pin the corrected
    // sequence: 'closed' must NOT fire if assertCleanupInvariants throws.
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        // shell.end() synchronously emits 'close' so we exercise the race.
        end: vi.fn(() => mockStream.emit('close')),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('race', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      // Stub assertCleanupInvariants to always throw — forces the race.
      (session as any).assertCleanupInvariants = function () {
        throw new SSHError('[contract] simulated late violation');
      };

      const onClosed = vi.fn();
      session.on('closed', onClosed);

      // close() is async (#304): the assertCleanupInvariants throw surfaces
      // as the returned promise's rejection. The 'closed' invariant — never
      // fired when the postcondition violated — is unchanged.
      await expect(session.close()).rejects.toThrow(/simulated late violation/);
      expect(onClosed).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("close() emits 'closed' once after assertCleanupInvariants passes", async () => {
    // Counterpart to the negative test above: confirm the happy path still
    // emits exactly one 'closed' event, and that it lands AFTER cleanup
    // completes (not synchronously from shell.end()).
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(() => mockStream.emit('close')),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('happy', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      const onClosed = vi.fn();
      session.on('closed', onClosed);

      session.close();
      expect(onClosed).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("stream-driven 'close' (unsolicited) still emits 'closed' so manager drops the reference", async () => {
    // Server-initiated disconnect path: close() never called, stream just
    // ended. Cleanup runs (defensive try/catch) and 'closed' is emitted so
    // the manager's createSession-registered 'closed' listener removes the
    // session from the map.
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('unsolicited', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      const onClosed = vi.fn();
      session.on('closed', onClosed);

      // Simulate the SSH server killing the stream.
      mockStream.emit('close');

      expect(onClosed).toHaveBeenCalledTimes(1);
      expect(session.getSessionInfo().isActive).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('createSession with a concurrent duplicate id rejects the second caller and does not orphan the first session', async () => {
    // Codex cycle-2 finding: `require_(!sessions.has(id))` is racy across
    // the `await getConnection` + `await initialize` boundary. Two
    // simultaneous calls with the same id both pass the guard and the
    // second sessions.set overwrites the first, orphaning the first
    // session outside manager ownership. The pendingSessionIds Set
    // reservation closes that race.
    vi.useFakeTimers();
    try {
      const manager = new SSHConnectionManager();
      const streamA = Object.assign(new EventEmitter(), {
        write: vi.fn(), end: vi.fn(), stderr: new EventEmitter(),
      });
      const clientA = Object.assign(new EventEmitter(), {
        shell: vi.fn((_opts: any, cb: any) => cb(null,streamA)),
      });

      // Stub getConnection so both concurrent calls would otherwise resolve
      // with the same client. (Tests the session-side race in isolation.)
      (manager as any).getConnection = vi.fn().mockResolvedValue(clientA);

      const p1 = manager.createSession('dup', 'h', 'u', 'interactive', '/tmp/k', { port: 22, mode: 'normal', timeoutMs: 600000 });
      // Synchronously kick the second call. The reservation must already
      // hold — otherwise its `!sessions.has('dup')` check would pass too.
      const p2 = manager.createSession('dup', 'h', 'u', 'interactive', '/tmp/k', { port: 22, mode: 'normal', timeoutMs: 600000 });

      await expect(p2).rejects.toBeInstanceOf(SSHError);
      await expect(p2).rejects.toThrow(/already exists/);

      await vi.advanceTimersByTimeAsync(1000);
      const winner = await p1;
      expect((manager as any).sessions.get('dup')).toBe(winner);
      expect((manager as any).sessions.size).toBe(1);
      expect((manager as any).pendingSessions.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('getConnection deduplicates concurrent callers for the same connection key', async () => {
    // Codex cycle-2 finding: the connection cache had the same check-then-
    // await shape. Concurrent createSession calls for different ids on the
    // same host would each create a new SSH client; one would win the
    // connections.set race, the loser would be orphaned. The
    // pendingConnections map joins concurrent creations into one.
    const manager = new SSHConnectionManager();
    const fakeClient = { fake: true } as unknown as Client;
    let createCallCount = 0;
    // Stub createConnection to count calls and resolve after a tick.
    (manager as any).createConnection = vi.fn(async () => {
      createCallCount += 1;
      await new Promise(r => setImmediate(r));
      return fakeClient;
    });

    const a = (manager as any).getConnection('h', 'u', '/k', 22) as Promise<Client>;
    const b = (manager as any).getConnection('h', 'u', '/k', 22) as Promise<Client>;
    const c = (manager as any).getConnection('h', 'u', '/k', 22) as Promise<Client>;

    const [ra, rb, rc] = await Promise.all([a, b, c]);
    expect(ra).toBe(fakeClient);
    expect(rb).toBe(fakeClient);
    expect(rc).toBe(fakeClient);
    expect(createCallCount).toBe(1);
    expect((manager as any).pendingConnections.size).toBe(0);
    expect((manager as any).connections.size).toBe(1);
  });
});

describe('Contract guards (lifecycle correctness — cycle 3)', () => {
  it("initialize() rejects if the shell closes during the startup delay", async () => {
    // Codex cycle-3 finding-4: prior implementation resolved initialize()
    // after a 1s setTimeout regardless of whether the stream survived.
    // A stream close during startup must reject so the caller does not
    // receive a session that's already dead.
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('init-die', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });

      const initPromise = session.initialize();
      // Kill the stream BEFORE the 1s settle fires.
      await vi.advanceTimersByTimeAsync(50);
      mockStream.emit('close');

      await expect(initPromise).rejects.toBeInstanceOf(SSHError);
      await expect(initPromise).rejects.toThrow(/closed during initialization/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("initialize() rejects on a shell error during startup", async () => {
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('init-err', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });

      const initPromise = session.initialize();
      await vi.advanceTimersByTimeAsync(50);
      mockStream.emit('error', new Error('boom'));

      await expect(initPromise).rejects.toBeInstanceOf(SSHError);
      await expect(initPromise).rejects.toThrow(/error during initialization/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("'closed' is emitted at most once even when shell.end() emits stream-close after close()", async () => {
    // Codex cycle-3 finding-2 + #304 codex review (class-finding): the
    // closedEmitted latch must prevent a double-emit when close()'s
    // remote-close await resolves AND a subsequent stream-close event
    // re-runs cleanup(). After the #304 fix, close() defers emitting
    // 'closed' until AFTER the remote-close latch resolves (or the
    // bounded timeout fires), so this test now stages the events in
    // that order: explicit stream emit → close() promise resolves
    // (and emits 'closed' via the latch's first winner) → second
    // stream emit must be a no-op.
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('latch', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      const onClosed = vi.fn();
      session.on('closed', onClosed);

      const closeP = session.close();
      // Before the remote 'close' fires, 'closed' has NOT been emitted —
      // the #304 fix guarantees the manager's session-id drop happens
      // only after the wrapper's flush window completes.
      await Promise.resolve();
      expect(onClosed).toHaveBeenCalledTimes(0);

      // First stream-close: stream.on('close') handler fires cleanup()
      // → emitClosedIfVerified emits 'closed' AND resolveRemoteClosed
      // unblocks the close() await.
      mockStream.emit('close');
      await closeP;
      expect(onClosed).toHaveBeenCalledTimes(1);

      // A second stream emit (delayed async ssh2 behavior) must be
      // a no-op via the closedEmitted latch.
      mockStream.emit('close');
      expect(onClosed).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("event-handler cleanup() failure emits 'error' (when listened) so manager drops the broken session", async () => {
    // Codex cycle-3 findings 2 + 3 (manager ownership): when stream-close
    // runs cleanup() and the postcondition fails, cleanup() must NOT emit
    // 'closed' (would falsely record success), but MUST emit 'error' so a
    // manager listener can drop the broken reference. Production attaches
    // the listener in createSession.
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      const session = new PersistentSession('error-emit', 'host', 'user', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      (session as any).assertCleanupInvariants = function () {
        throw new SSHError('[contract] simulated stream-close violation');
      };

      const onClosed = vi.fn();
      const onError = vi.fn();
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      session.on('closed', onClosed);
      session.on('error', onError);

      try {
        // Unsolicited stream close — close() was never called.
        mockStream.emit('close');

        expect(onClosed).not.toHaveBeenCalled();
        expect(onError).toHaveBeenCalledTimes(1);
        expect(onError.mock.calls[0][0]).toBeInstanceOf(SSHError);
        expect(onError.mock.calls[0][0].message).toMatch(/simulated stream-close violation/);
      } finally {
        errorSpy.mockRestore();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("'timeout' event does NOT delete the manager's session reference (only 'closed'/'error' transfer ownership)", async () => {
    // Codex cycle-3 finding-3: previously the manager deleted on 'timeout'
    // BEFORE close() could observe its postcondition. The 'timeout' listener
    // is now informational; close() runs next inside resetSessionTimeout's
    // try/catch and fires 'closed' (success) or 'error' (failure), and
    // THOSE listeners transfer ownership.
    vi.useFakeTimers();
    try {
      const manager = new SSHConnectionManager();
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),  // DOES NOT emit 'close' — simulates a stuck stream
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;
      (manager as any).getConnection = vi.fn().mockResolvedValue(mockClient);

      const createP = manager.createSession('timer-test', 'h', 'u', 'interactive', '/k', { port: 22, mode: 'normal', timeoutMs: 600000 });
      await vi.advanceTimersByTimeAsync(1000);
      const session = await createP;
      expect(manager.getSession('timer-test')).toBe(session);

      // Fire the timeout listener directly (no real timer) to isolate the
      // ownership-transfer semantics from the timer-callback close() chain.
      session.emit('timeout');
      // 'timeout' listener should NOT have deleted the session.
      expect(manager.getSession('timer-test')).toBe(session);
    } finally {
      vi.useRealTimers();
    }
  });

  it("disconnectAll() quiesces in-flight createSession before sweeping", async () => {
    // Codex cycle-3 finding-1: a createSession reserved its id but hadn't
    // sessions.set() it when disconnectAll snapshotted the established map.
    // Without quiescing, the create completes after teardown and repopulates
    // the manager. With pendingSessions awaited, the create either finishes
    // (and the session is in this.sessions, which gets swept) or fails.
    vi.useFakeTimers();
    try {
      const manager = new SSHConnectionManager();
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(() => mockStream.emit('close')),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null,mockStream)) } as any;

      // Make getConnection slow enough to overlap with disconnectAll.
      let releaseGetConn: (client: Client) => void;
      const getConnPromise = new Promise<Client>(r => { releaseGetConn = r; });
      (manager as any).getConnection = vi.fn().mockReturnValue(getConnPromise);

      // Kick off createSession; it's now in pendingSessions, waiting on
      // getConnection.
      const createP = manager.createSession('inflight', 'h', 'u', 'interactive', '/k', { port: 22, mode: 'normal', timeoutMs: 600000 });
      expect((manager as any).pendingSessions.size).toBe(1);

      // Kick off disconnectAll. It MUST await pendingSessions before sweeping.
      const disconnectP = manager.disconnectAll();

      // Now release getConnection so the create can proceed.
      releaseGetConn!(mockClient);
      await vi.advanceTimersByTimeAsync(1000);

      // Both should resolve cleanly; the session that landed during the
      // create gets swept by disconnectAll, so the manager ends empty.
      await createP;
      await disconnectP;
      expect((manager as any).sessions.size).toBe(0);
      expect((manager as any).pendingSessions.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

// Helper for the effective-mode + awaitable-close suites below. Driving a
// command-and-response through the mock shell is identical in every test —
// extract it so each `it` block reads as "construct → drive → assert".
async function driveCommand(
  session: PersistentSession,
  mockStream: EventEmitter & { write: ReturnType<typeof vi.fn> },
  command: string,
  output: string,
  exitCode: number,
  raw?: boolean,
): Promise<import('../src/ssh.js').CommandResult> {
  const promise = session.executeCommand(command, 60000, raw);
  // For normal-mode commands the parser keys on the delimiter; for raw-mode
  // commands the timeout resolves with collected output.
  const delimiter = (session as any).commandDelimiter;
  const cmdId = (session as any).currentCommand?.id;
  if (raw === true || (raw === undefined && session.getSessionInfo().mode === 'raw')) {
    // Raw path: deliver output then advance past the per-command timeout.
    mockStream.emit('data', Buffer.from(output));
    await vi.advanceTimersByTimeAsync(60000);
  } else {
    const startMarker = `${delimiter}_START_${cmdId}`;
    const endMarker = `${delimiter}_END_${cmdId}`;
    mockStream.emit('data', Buffer.from(`${startMarker}\n${output}\n${endMarker}:${exitCode}\n`));
  }
  return promise;
}

describe('OBS-003 / #282: effective session-mode metadata in CommandResult', () => {
  let mockStream: EventEmitter & { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn>; stderr: EventEmitter };
  let mockClient: any;

  beforeEach(async () => {
    vi.useFakeTimers();
    mockStream = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null, mockStream)) };
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("executeCommand on a normal session with no override resolves with mode: 'normal'", async () => {
    const session = new PersistentSession('em-1', 'h', 'u', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    const result = await driveCommand(session, mockStream, 'echo hi', 'hi', 0);
    expect(result.mode).toBe('normal');
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('hi');
  });

  it("executeCommand on a RAW session with no override resolves with mode: 'raw' (the inherited-raw case from issue #282)", async () => {
    const session = new PersistentSession('em-2', 'h', 'u', 'background', mockClient, { port: 22, mode: 'raw', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    const result = await driveCommand(session, mockStream, 'msfconsole', 'msf6 >', 0);
    expect(result.mode).toBe('raw');
    // raw mode resolves with code 0 by design, but `mode` carries the
    // unknown-outcome signal that downstream observability consumes.
    expect(result.code).toBe(0);
  });

  it("per-call raw: true override on a normal session resolves with mode: 'raw'", async () => {
    const session = new PersistentSession('em-3', 'h', 'u', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    const result = await driveCommand(session, mockStream, 'something', 'out', 0, true);
    expect(result.mode).toBe('raw');
  });

  it("per-call raw: false override on a RAW session resolves with mode: 'normal'", async () => {
    const session = new PersistentSession('em-4', 'h', 'u', 'interactive', mockClient, { port: 22, mode: 'raw', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    const result = await driveCommand(session, mockStream, 'echo hi', 'hi', 0, false);
    expect(result.mode).toBe('normal');
  });

  it("background-session immediate-return envelope carries effective mode (inherited raw)", async () => {
    const session = new PersistentSession('em-5', 'h', 'u', 'background', mockClient, { port: 22, mode: 'raw', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    // Background sessions resolve immediately with a queued envelope; no
    // delimiter dance, no advanceTimers needed.
    const result = await session.executeCommand('long-running', 60000);
    expect(result.mode).toBe('raw');
    // The queued-envelope contract from ssh.ts: stdout describes the queue,
    // code is 0. The new `mode` field reflects the effective mode at queue time.
    expect(result.stdout).toContain('queued in background');
  });
});

describe('#304: PersistentSession.close() awaits remote stream-close', () => {
  let mockStream: EventEmitter & { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn>; stderr: EventEmitter };
  let mockClient: any;

  beforeEach(async () => {
    vi.useFakeTimers();
    mockStream = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(), // does NOT auto-emit 'close' — tests drive it manually
      stderr: new EventEmitter(),
    });
    mockClient = { shell: vi.fn((_opts: any, cb: any) => cb(null, mockStream)) };
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("close() returns a Promise that resolves only after the stream's 'close' event fires", async () => {
    const session = new PersistentSession('aw-1', 'h', 'u', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    const closeP = session.close();
    let resolved = false;
    closeP.then(() => { resolved = true; });

    // The Kali ForceCommand wrapper needs its child shell to exit normally so
    // `script(1)` closes the transcript FIFO and the capture client can flush
    // before sshd closes the channel. Bare EOF truncated live captures.
    expect(mockStream.end).toHaveBeenCalledWith('exit\n');

    // Microtask drain — local cleanup is sync, but the close promise must
    // still be pending because remote 'close' has not fired.
    await Promise.resolve();
    await Promise.resolve();
    expect(resolved).toBe(false);

    // Fire the remote close; close() resolves.
    mockStream.emit('close');
    await closeP;
    expect(resolved).toBe(true);
  });

  it("close() resolves after the bounded timeout when stream 'close' never fires, and logs a [SSH] warning", async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const session = new PersistentSession('aw-2', 'h', 'u', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      const closeP = session.close();
      let resolved = false;
      closeP.then(() => { resolved = true; });

      // Just shy of the timeout — promise is still pending.
      await vi.advanceTimersByTimeAsync(2999);
      expect(resolved).toBe(false);

      // Past the timeout — promise resolves.
      await vi.advanceTimersByTimeAsync(2);
      await closeP;
      expect(resolved).toBe(true);

      const matched = errorSpy.mock.calls.some(call =>
        typeof call[0] === 'string' && call[0].includes('[SSH] remote close timeout')
      );
      expect(matched).toBe(true);
    } finally {
      errorSpy.mockRestore();
    }
  });

  it("in-flight and queued command rejections happen BEFORE close()'s remote-await resolves", async () => {
    const session = new PersistentSession('aw-3', 'h', 'u', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    const inFlight = session.executeCommand('p1', 60000);
    const queued1 = session.executeCommand('p2', 60000);
    const queued2 = session.executeCommand('p3', 60000);

    // Capture order: rejections must settle before closeP — observable via the
    // microtask queue. Track resolution order with timestamps.
    const events: string[] = [];
    inFlight.catch(() => events.push('inFlight'));
    queued1.catch(() => events.push('queued1'));
    queued2.catch(() => events.push('queued2'));

    const closeP = session.close();
    closeP.then(() => events.push('close'));

    // Drain microtasks WITHOUT firing remote close yet — rejections should
    // already have landed because cleanup runs synchronously inside close().
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(events).toContain('inFlight');
    expect(events).toContain('queued1');
    expect(events).toContain('queued2');
    expect(events).not.toContain('close');

    mockStream.emit('close');
    await closeP;
    expect(events[events.length - 1]).toBe('close');
  });

  it("SSHConnectionManager.closeSession() awaits the remote close before returning", async () => {
    const manager = new SSHConnectionManager();
    (manager as any).getConnection = vi.fn().mockResolvedValue(mockClient);

    const createP = manager.createSession('aw-mgr', 'h', 'u', 'interactive', '/k', { port: 22, mode: 'normal', timeoutMs: 600000 });
    await vi.advanceTimersByTimeAsync(1000);
    await createP;

    let resolved = false;
    const closeP = manager.closeSession('aw-mgr').then(v => { resolved = true; return v; });

    // Microtask drain — manager promise should NOT resolve before remote close.
    await Promise.resolve();
    await Promise.resolve();
    expect(resolved).toBe(false);

    mockStream.emit('close');
    const result = await closeP;
    expect(result).toBe(true);
    expect(resolved).toBe(true);
  });

  it("close() does NOT emit 'closed' before the remote-close await settles (the manager must not release the id while captures are still flushing)", async () => {
    // Codex pre-push review (class-finding): emitClosedIfVerified must run
    // AFTER the bounded remote-close await, otherwise a concurrent caller
    // can re-create the same session id while the old wrapper's EXIT trap
    // is still flushing tcpdump / typescript captures.
    const session = new PersistentSession('order-1', 'h', 'u', 'interactive', mockClient, { port: 22, mode: 'normal', timeoutMs: 600000 });
    const initP = session.initialize();
    await vi.advanceTimersByTimeAsync(1000);
    await initP;

    const onClosed = vi.fn();
    session.on('closed', onClosed);

    const closeP = session.close();
    // Several microtask ticks must NOT cause 'closed' to fire — the
    // remote latch is unresolved and the timeout has not elapsed.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(onClosed).toHaveBeenCalledTimes(0);

    // Releasing the remote close lets close() finish; the 'closed'
    // signal lands at that point, not before.
    mockStream.emit('close');
    await closeP;
    expect(onClosed).toHaveBeenCalledTimes(1);
  });

  it("disconnectAll() awaits every session close BEFORE tearing down the parent SSH transport", async () => {
    // Codex pre-push review (class-finding): client.end() must not fire
    // while session.close() is still awaiting its remote close. Otherwise
    // the parent transport drops while channels are still draining.
    const manager = new SSHConnectionManager();

    const streamA = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    const clientEnd = vi.fn();
    const sharedClient: any = Object.assign(new EventEmitter(), {
      shell: vi.fn((_opts: any, cb: any) => cb(null, streamA)),
      end: clientEnd,
    });
    (manager as any).getConnection = vi.fn().mockResolvedValue(sharedClient);
    (manager as any).connections.set('u@h:22', { client: sharedClient, connected: true });

    const createA = manager.createSession('a', 'h', 'u', 'interactive', '/k', { port: 22, mode: 'normal', timeoutMs: 600000 });
    await vi.advanceTimersByTimeAsync(1000);
    await createA;

    const disconnectP = manager.disconnectAll();
    // client.end() MUST NOT have been called yet — sessions are still
    // awaiting remote close. Drain several microtask ticks to confirm
    // the ordering is not just "not yet" but "actively blocked on the
    // session close phase".
    for (let i = 0; i < 10; i += 1) await Promise.resolve();
    expect(clientEnd).not.toHaveBeenCalled();

    // Release the session's remote close. Session.close() now resolves
    // and disconnectAll progresses to the connection teardown phase.
    streamA.emit('close');
    // Drain microtasks past session-close → teardown-helper listener
    // registration. Only THEN can we emit the connection-close that
    // settles teardown's `emitter.once('close', ...)`.
    for (let i = 0; i < 20; i += 1) await Promise.resolve();
    expect(clientEnd).toHaveBeenCalledTimes(1);
    sharedClient.emit('close');
    await disconnectP;
  });

  it("disconnectAll() awaits every session's remote close before clearing the map", async () => {
    const manager = new SSHConnectionManager();

    // Two separate mock streams so each session has its own close gate.
    const streamA = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    const streamB = Object.assign(new EventEmitter(), {
      write: vi.fn(),
      end: vi.fn(),
      stderr: new EventEmitter(),
    });
    let i = 0;
    const sharedClient: any = {
      shell: vi.fn((_opts: any, cb: any) => {
        cb(null, i === 0 ? streamA : streamB);
        i += 1;
      }),
    };
    (manager as any).getConnection = vi.fn().mockResolvedValue(sharedClient);

    const createA = manager.createSession('a', 'h', 'u', 'interactive', '/k', { port: 22, mode: 'normal', timeoutMs: 600000 });
    await vi.advanceTimersByTimeAsync(1000);
    await createA;
    const createB = manager.createSession('b', 'h', 'u', 'interactive', '/k', { port: 22, mode: 'normal', timeoutMs: 600000 });
    await vi.advanceTimersByTimeAsync(1000);
    await createB;

    let resolved = false;
    const disconnectP = manager.disconnectAll().then(() => { resolved = true; });

    await Promise.resolve();
    await Promise.resolve();
    expect(resolved).toBe(false);

    streamA.emit('close');
    await Promise.resolve();
    expect(resolved).toBe(false); // B still pending

    streamB.emit('close');
    await disconnectP;
    expect(resolved).toBe(true);
    expect((manager as any).sessions.size).toBe(0);
  });
});
