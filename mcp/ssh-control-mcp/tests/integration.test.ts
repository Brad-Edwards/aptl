import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SSHConnectionManager } from '../src/ssh.js';
import { Client } from 'ssh2';

vi.mock('ssh2');
vi.mock('fs/promises');

describe('SSH Integration Tests', () => {
  let manager: SSHConnectionManager;

  beforeEach(() => {
    manager = new SSHConnectionManager();
    vi.clearAllMocks();
  });

  describe('SSHConnectionManager', () => {
    it('should create a manager instance', () => {
      expect(manager).toBeDefined();
      expect(manager).toBeInstanceOf(SSHConnectionManager);
    });

    it('should list sessions as empty initially', () => {
      const sessions = manager.listSessions();
      expect(sessions).toEqual([]);
    });

    it('should return undefined for non-existent session', () => {
      const session = manager.getSession('non-existent');
      expect(session).toBeUndefined();
    });

    it('should return false when closing non-existent session', async () => {
      const result = await manager.closeSession('non-existent');
      expect(result).toBe(false);
    });

    it('should throw error when executing in non-existent session', async () => {
      await expect(
        manager.executeInSession('non-existent', 'ls')
      ).rejects.toThrow("Session 'non-existent' not found");
    });

    it('should throw error when getting output from non-existent session', () => {
      expect(() => {
        manager.getSessionOutput('non-existent');
      }).toThrow("Session 'non-existent' not found");
    });

    // Note: Full integration tests with real SSH connections would require
    // a test SSH server or more complex mocking of the ssh2 library
  });
});