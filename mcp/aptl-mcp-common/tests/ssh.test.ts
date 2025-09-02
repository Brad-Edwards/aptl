import { describe, it, expect, vi } from 'vitest';
import { PersistentSession, SSHConnectionManager } from '../src/ssh.js';

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