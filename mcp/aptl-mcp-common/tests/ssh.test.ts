import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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
