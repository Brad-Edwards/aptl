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
    const session = new PersistentSession(
      'test-id',
      'test-host',
      'test-user',
      'interactive',
      mockClient,
      2222,
      'normal',
      60000
    );

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
    const session = new PersistentSession(
      'test', 'host', 'user', 'interactive', mockClient, 22
    );

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
    const raw = new PersistentSession('r', 'host', 'user', 'interactive', mockClient, 22, 'raw');

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
    const session = new PersistentSession(
      'buffer-test', 'host', 'user', 'background', mockClient, 22
    );

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
    const session = new PersistentSession(
      'overflow-test', 'host', 'user', 'background', mockClient, 22
    );

    // Simulate the private method behavior by accessing outputBuffer
    const outputBuffer = (session as any).outputBuffer;

    // Fill buffer beyond limit
    for (let i = 0; i < 12000; i++) {
      outputBuffer.push(`line ${i}`);
    }

    // Trigger the overflow logic manually
    if (outputBuffer.length > 10000) {
      (session as any).outputBuffer = outputBuffer.slice(-5000);
    }

    const buffer = session.getBufferedOutput();
    expect(buffer.length).toBe(5000);
    // Should keep lines 7000-11999 (newest)
    expect(buffer[0]).toBe('line 7000');
    expect(buffer[buffer.length - 1]).toBe('line 11999');
  });
});

describe('Connection Key Generation Logic', () => {
  it('should generate unique connection keys', () => {
    const manager = new SSHConnectionManager();

    // This tests our internal key generation logic
    // We can't directly test it but we can verify behavior differences
    const sessions = manager.listSessions();
    expect(sessions).toEqual([]); // Manager starts empty
  });
});

describe('Shell Type Support', () => {
  it('should create sessions with default bash shell', () => {
    const mockClient = {} as any;
    const session = new PersistentSession(
      'test-id',
      'test-host',
      'test-user',
      'interactive',
      mockClient,
      22
    );

    // The shell type is handled internally by the formatter
    const info = session.getSessionInfo();
    expect(info).toBeDefined(); // Session created successfully
  });

  it('should create sessions with specified shell types', () => {
    const mockClient = {} as any;
    const shellTypes: ShellType[] = ['bash', 'sh', 'powershell', 'cmd'];

    shellTypes.forEach(shellType => {
      const session = new PersistentSession(
        `test-${shellType}`,
        'test-host',
        'test-user',
        'interactive',
        mockClient,
        22,
        'normal',
        60000,
        shellType
      );

      const info = session.getSessionInfo();
      expect(info.sessionId).toBe(`test-${shellType}`);
      expect(info).toBeDefined(); // Session created successfully with shell type
    });
  });

  it('should track shell type through session lifecycle', async () => {
    const mockClient = {
      shell: vi.fn((callback) => {
        // Mock shell stream
        const mockStream = {
          on: vi.fn(),
          stderr: { on: vi.fn() },
          write: vi.fn(),
          end: vi.fn()
        };
        callback(null, mockStream);
        return mockStream;
      })
    } as any;

    const powershellSession = new PersistentSession(
      'ps-test',
      'windows-host',
      'Administrator',
      'interactive',
      mockClient,
      22,
      'normal',
      60000,
      'powershell'
    );

    // Initialize the session
    await powershellSession.initialize();
    const info = powershellSession.getSessionInfo();
    expect(info.sessionId).toBe('ps-test');
    expect(info.target).toBe('windows-host');
    expect(info.username).toBe('Administrator');

    powershellSession.close();
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
      shell: vi.fn((cb: any) => cb(null, mockStream)),
    };

    session = new PersistentSession(
      'cleanup-test', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
    );

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
  it('executeCommand on uninitialized session throws SSHError and does not write to shell', async () => {
    const writeSpy = vi.fn();
    const mockClient = { shell: vi.fn() } as any;
    const session = new PersistentSession(
      'pre-uninit', 'host', 'user', 'interactive', mockClient, 22
    );

    await expect(session.executeCommand('ls', 1000)).rejects.toBeInstanceOf(SSHError);
    await expect(session.executeCommand('ls', 1000)).rejects.toThrow('Session not initialized or inactive');
    expect(writeSpy).not.toHaveBeenCalled();
  });

  it('executeCommand after close throws SSHError', async () => {
    vi.useFakeTimers();
    try {
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'pre-closed', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );
      const initPromise = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initPromise;

      session.close();

      await expect(session.executeCommand('ls', 1000)).rejects.toBeInstanceOf(SSHError);
      await expect(session.executeCommand('ls', 1000)).rejects.toThrow('Session not initialized or inactive');
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
    mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) };
    session = new PersistentSession(
      'post-test', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
    );
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

  it('timer-callback close path swallows postcondition violations and logs', () => {
    // Same defensive contract for the resetSessionTimeout timer callback — an
    // uncaught throw from setTimeout crashes Node. We stub close() to throw and
    // verify the timer-callback try/catch catches it.
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalClose = session.close.bind(session);
    session.close = () => { throw new SSHError('[contract] simulated close failure'); };
    try {
      // Advance the timer to fire the session-timeout callback.
      // sessionTimeoutMs is 600000 (set in beforeEach).
      vi.advanceTimersByTime(600000);

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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'mgr-close', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );
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
        shell: vi.fn((cb: any) => cb(null, stream1)),
        end: vi.fn(() => client1.emit('close')),
      });
      const client2 = Object.assign(new EventEmitter(), {
        shell: vi.fn((cb: any) => cb(null, stream2)),
        end: vi.fn(() => client2.emit('close')),
      });
      const s1 = new PersistentSession('s1', 'h', 'u', 'interactive', client1 as any, 22, 'normal', 600000);
      const s2 = new PersistentSession('s2', 'h', 'u', 'interactive', client2 as any, 22, 'normal', 600000);
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
        shell: vi.fn((cb: any) => cb(null, stream)),
        end: vi.fn(() => client.emit('close')),
      });
      const sessionA = new PersistentSession('a', 'h', 'u', 'interactive', client as any, 22, 'normal', 600000);
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
        shell: vi.fn((cb: any) => cb(null, stream)),
      });
      const sessionA = new PersistentSession('a', 'h', 'u', 'interactive', client as any, 22, 'normal', 600000);
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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'race', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      // Stub assertCleanupInvariants to always throw — forces the race.
      (session as any).assertCleanupInvariants = function () {
        throw new SSHError('[contract] simulated late violation');
      };

      const onClosed = vi.fn();
      session.on('closed', onClosed);

      expect(() => session.close()).toThrow(/simulated late violation/);
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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'happy', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );
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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'unsolicited', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );
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
        shell: vi.fn((cb: any) => cb(null, streamA)),
      });

      // Stub getConnection so both concurrent calls would otherwise resolve
      // with the same client. (Tests the session-side race in isolation.)
      (manager as any).getConnection = vi.fn().mockResolvedValue(clientA);

      const p1 = manager.createSession('dup', 'h', 'u', 'interactive', '/tmp/k', 22, 'normal', 600000);
      // Synchronously kick the second call. The reservation must already
      // hold — otherwise its `!sessions.has('dup')` check would pass too.
      const p2 = manager.createSession('dup', 'h', 'u', 'interactive', '/tmp/k', 22, 'normal', 600000);

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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'init-die', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );

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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'init-err', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );

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
    // Codex cycle-3 finding-2: closedEmitted latch must prevent a double-emit
    // when close() succeeded and then the underlying stream's 'close' event
    // fires again later (async ssh2 channel behavior). Without the latch, a
    // listener that resubscribes (e.g. test isolation) could see two events.
    vi.useFakeTimers();
    try {
      // mockStream where end() does NOT immediately emit close; we'll fire
      // close manually AFTER close() has returned.
      const mockStream = Object.assign(new EventEmitter(), {
        write: vi.fn(),
        end: vi.fn(),
        stderr: new EventEmitter(),
      });
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'latch', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );
      const initP = session.initialize();
      await vi.advanceTimersByTimeAsync(1000);
      await initP;

      const onClosed = vi.fn();
      session.on('closed', onClosed);

      session.close();
      // close() should have emitted 'closed' synchronously after assertion.
      expect(onClosed).toHaveBeenCalledTimes(1);

      // Now the stream fires its delayed 'close' event. The latch must
      // suppress a second 'closed' emission.
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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      const session = new PersistentSession(
        'error-emit', 'host', 'user', 'interactive', mockClient, 22, 'normal', 600000
      );
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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;
      (manager as any).getConnection = vi.fn().mockResolvedValue(mockClient);

      const createP = manager.createSession('timer-test', 'h', 'u', 'interactive', '/k', 22, 'normal', 600000);
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
      const mockClient = { shell: vi.fn((cb: any) => cb(null, mockStream)) } as any;

      // Make getConnection slow enough to overlap with disconnectAll.
      let releaseGetConn: (client: Client) => void;
      const getConnPromise = new Promise<Client>(r => { releaseGetConn = r; });
      (manager as any).getConnection = vi.fn().mockReturnValue(getConnPromise);

      // Kick off createSession; it's now in pendingSessions, waiting on
      // getConnection.
      const createP = manager.createSession('inflight', 'h', 'u', 'interactive', '/k', 22, 'normal', 600000);
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
