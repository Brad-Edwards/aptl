import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateToolHandlers } from '../../src/tools/handlers.js';
import type { ToolContext } from '../../src/tools/handlers.js';
import type { LabConfig } from '../../src/config.js';
import { SSHConnectionManager } from '../../src/ssh.js';

// Mock the SSH connection manager and config functions
vi.mock('../../src/ssh.js');
vi.mock('../../src/config.js', async () => {
  const actual = await vi.importActual('../../src/config.js');
  return {
    ...actual,
    getTargetCredentials: vi.fn()
  };
});

const { getTargetCredentials } = await import('../../src/config.js');
const mockGetTargetCredentials = vi.mocked(getTargetCredentials);

describe('Tool Handler Tests', () => {
  let mockSSHManager: SSHConnectionManager;
  let testLabConfig: LabConfig;
  let toolContext: ToolContext;

  beforeEach(() => {
    vi.clearAllMocks();
    
    // Setup mock SSH manager
    mockSSHManager = {
      executeCommand: vi.fn(),
      createSession: vi.fn(),
      executeInSession: vi.fn(),
      listSessions: vi.fn(),
      closeSession: vi.fn(),
      getSession: vi.fn(),
      disconnectAll: vi.fn(),
      getSessionOutput: vi.fn()
    } as any;

    // Setup test lab config
    testLabConfig = {
      version: '1.0.0',
      server: {
        name: 'test-server',
        version: '1.0.0',
        description: 'Test server',
        toolPrefix: 'test',
        targetName: 'Test Target',
        configKey: 'test-container',
        envPrefix: 'TEST'
      },
      lab: {
        name: 'test-lab',
        network_subnet: '172.20.0.0/16'
      },
      containers: {
        'test-container': {
          container_name: 'aptl-test',
          container_ip: '172.20.0.30',
          ssh_key: '~/.ssh/test_key',
          ssh_user: 'testuser',
          ssh_port: 2222,
          enabled: true
        }
      },
      mcp: {
        server_name: 'test-mcp',
        allowed_networks: ['172.20.0.0/16'],
        max_session_time: 3600,
        audit_enabled: true,
        log_level: 'info'
      }
    };

    toolContext = {
      sshManager: mockSSHManager,
      labConfig: testLabConfig
    };

    // Setup default mock return value for getTargetCredentials
    mockGetTargetCredentials.mockReturnValue({
      sshKey: '~/.ssh/test_key',
      username: 'testuser',
      port: 2222,
      target: '172.20.0.30'
    });
  });

  describe('generateToolHandlers - Basic Functionality', () => {
    it('should map tool names to handlers correctly', () => {
      const handlers = generateToolHandlers(testLabConfig.server);
      
      const expectedToolNames = [
        'test_info',
        'test_run_command',
        'test_interactive_session',
        'test_background_session',
        'test_session_command',
        'test_list_sessions',
        'test_close_session',
        'test_get_session_output',
        'test_close_all_sessions'
      ];

      expectedToolNames.forEach(toolName => {
        expect(handlers).toHaveProperty(toolName);
        expect(typeof handlers[toolName]).toBe('function');
      });
    });

    it('should generate handlers with different tool prefixes', () => {
      const kaliConfig: LabConfig['server'] = {
        name: 'kali-server',
        version: '1.0.0',
        description: 'Kali server',
        toolPrefix: 'kali',
        targetName: 'Kali Linux',
        configKey: 'kali',
        envPrefix: 'KALI'
      };

      const handlers = generateToolHandlers(kaliConfig);
      
      expect(handlers).toHaveProperty('kali_info');
      expect(handlers).toHaveProperty('kali_run_command');
      expect(handlers).toHaveProperty('kali_interactive_session');
      expect(handlers).not.toHaveProperty('test_info');
    });

    it('should ensure all base handlers are accessible', () => {
      const handlers = generateToolHandlers(testLabConfig.server);
      
      // Each handler should be a function
      Object.values(handlers).forEach(handler => {
        expect(typeof handler).toBe('function');
      });
    });
  });

  describe('target_info Handler', () => {
    it('should return container information when enabled', async () => {
      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_info']({}, toolContext);

      expect(result).toHaveProperty('content');
      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');
      
      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        target_ip: '172.20.0.30',
        ssh_user: 'testuser',
        ssh_port: 2222,
        lab_name: 'test-lab',
        lab_network: '172.20.0.0/16',
        target_name: 'Test Target',
        note: 'Use Test Target for operations in this container.'
      });
    });

    it('should return disabled message when container is disabled', async () => {
      const disabledConfig = {
        ...testLabConfig,
        containers: {
          'test-container': {
            ...testLabConfig.containers['test-container'],
            enabled: false
          }
        }
      };

      const disabledContext = {
        ...toolContext,
        labConfig: disabledConfig
      };

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_info']({}, disabledContext);

      expect(result.content[0].text).toBe(
        'Test Target instance is not enabled in the current lab configuration.'
      );
    });
  });

  describe('run_command Handler', () => {
    it('should execute command successfully', async () => {
      const mockOutput = 'Command executed successfully';
      mockSSHManager.executeCommand = vi.fn().mockResolvedValue(mockOutput);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_run_command']({ command: 'ls -la' }, toolContext);

      expect(mockSSHManager.executeCommand).toHaveBeenCalledWith(
        '172.20.0.30',
        'testuser',
        '~/.ssh/test_key',
        'ls -la',
        2222
      );

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        target: '172.20.0.30',
        command: 'ls -la',
        username: 'testuser',
        success: true,
        output: mockOutput
      });
    });

    it('should handle command execution errors', async () => {
      const errorMessage = 'Connection failed';
      mockSSHManager.executeCommand = vi.fn().mockRejectedValue(new Error(errorMessage));

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_run_command']({ command: 'invalid-command' }, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        command: 'invalid-command',
        success: false,
        error: errorMessage
      });
    });

    it('should handle non-Error exceptions', async () => {
      mockSSHManager.executeCommand = vi.fn().mockRejectedValue('String error');

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_run_command']({ command: 'test' }, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(false);
      expect(responseData.error).toBe('Unknown error');
    });
  });

  describe('interactive_session Handler', () => {
    it('should create interactive session with auto-generated ID', async () => {
      const mockSession = {
        getSessionInfo: vi.fn().mockReturnValue({
          sessionId: 'session_123_abc456',
          target: '172.20.0.30',
          username: 'testuser',
          createdAt: new Date('2023-01-01T00:00:00Z')
        })
      };

      mockSSHManager.createSession = vi.fn().mockResolvedValue(mockSession);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_interactive_session']({}, toolContext);

      expect(mockSSHManager.createSession).toHaveBeenCalledWith(
        expect.stringMatching(/^session_\d+_[a-z0-9]{6}$/),
        '172.20.0.30',
        'testuser',
        'interactive',
        '~/.ssh/test_key',
        2222,
        'normal',
        600000
      );

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(true);
      expect(responseData.type).toBe('interactive');
      expect(responseData.mode).toBe('normal');
    });

    it('should create interactive session with provided ID and timeout', async () => {
      const mockSession = {
        getSessionInfo: vi.fn().mockReturnValue({
          sessionId: 'custom-session-id',
          target: '172.20.0.30',
          username: 'testuser',
          createdAt: new Date('2023-01-01T00:00:00Z')
        })
      };

      mockSSHManager.createSession = vi.fn().mockResolvedValue(mockSession);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_interactive_session']({
        session_id: 'custom-session-id',
        timeout_ms: 300000
      }, toolContext);

      expect(mockSSHManager.createSession).toHaveBeenCalledWith(
        'custom-session-id',
        '172.20.0.30',
        'testuser',
        'interactive',
        '~/.ssh/test_key',
        2222,
        'normal',
        300000
      );
    });
  });

  describe('background_session Handler', () => {
    it('should create background session in normal mode by default', async () => {
      const mockSession = {
        getSessionInfo: vi.fn().mockReturnValue({
          sessionId: 'bg_session_123_abc456',
          target: '172.20.0.30',
          username: 'testuser',
          createdAt: new Date('2023-01-01T00:00:00Z')
        })
      };

      mockSSHManager.createSession = vi.fn().mockResolvedValue(mockSession);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_background_session']({}, toolContext);

      expect(mockSSHManager.createSession).toHaveBeenCalledWith(
        expect.stringMatching(/^bg_session_\d+_[a-z0-9]{6}$/),
        '172.20.0.30',
        'testuser',
        'background',
        '~/.ssh/test_key',
        2222,
        'normal',
        600000
      );

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(true);
      expect(responseData.type).toBe('background');
      expect(responseData.mode).toBe('normal');
      expect(responseData.message).not.toContain('raw mode');
    });

    it('should create background session in raw mode when requested', async () => {
      const mockSession = {
        getSessionInfo: vi.fn().mockReturnValue({
          sessionId: 'bg_session_raw_123',
          target: '172.20.0.30',
          username: 'testuser',
          createdAt: new Date('2023-01-01T00:00:00Z')
        })
      };

      mockSSHManager.createSession = vi.fn().mockResolvedValue(mockSession);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_background_session']({
        session_id: 'bg_session_raw_123',
        raw: true
      }, toolContext);

      expect(mockSSHManager.createSession).toHaveBeenCalledWith(
        'bg_session_raw_123',
        '172.20.0.30',
        'testuser',
        'background',
        '~/.ssh/test_key',
        2222,
        'raw',
        600000
      );

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.mode).toBe('raw');
      expect(responseData.message).toContain('raw mode for interactive programs');
    });
  });

  describe('session_command Handler', () => {
    it('should execute command in session successfully', async () => {
      const mockResult = {
        stdout: 'Command output',
        stderr: '',
        code: 0
      };

      mockSSHManager.executeInSession = vi.fn().mockResolvedValue(mockResult);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_session_command']({
        session_id: 'session-123',
        command: 'echo hello'
      }, toolContext);

      expect(mockSSHManager.executeInSession).toHaveBeenCalledWith(
        'session-123',
        'echo hello',
        30000,
        undefined
      );

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        success: true,
        session_id: 'session-123',
        command: 'echo hello',
        output: 'Command output',
        stderr: '',
        exit_code: 0
      });
    });

    it('should use custom timeout and raw mode when provided', async () => {
      const mockResult = {
        stdout: 'Raw command output',
        stderr: '',
        code: 0
      };

      mockSSHManager.executeInSession = vi.fn().mockResolvedValue(mockResult);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_session_command']({
        session_id: 'raw-session',
        command: 'msfconsole -q',
        timeout: 60000,
        raw: true
      }, toolContext);

      expect(mockSSHManager.executeInSession).toHaveBeenCalledWith(
        'raw-session',
        'msfconsole -q',
        60000,
        true
      );
    });
  });

  describe('list_sessions Handler', () => {
    it('should list all sessions successfully', async () => {
      const mockSessions = [
        {
          sessionId: 'session-1',
          target: '172.20.0.30',
          username: 'testuser',
          type: 'interactive',
          mode: 'normal',
          createdAt: new Date('2023-01-01T00:00:00Z'),
          lastActivity: new Date('2023-01-01T00:05:00Z'),
          isActive: true,
          commandHistory: ['ls', 'pwd']
        },
        {
          sessionId: 'session-2',
          target: '172.20.0.30',
          username: 'testuser',
          type: 'background',
          mode: 'raw',
          createdAt: new Date('2023-01-01T00:10:00Z'),
          lastActivity: new Date('2023-01-01T00:15:00Z'),
          isActive: false,
          commandHistory: ['msfconsole']
        }
      ];

      mockSSHManager.listSessions = vi.fn().mockReturnValue(mockSessions);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_list_sessions']({}, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(true);
      expect(responseData.total_sessions).toBe(2);
      expect(responseData.sessions).toHaveLength(2);
      expect(responseData.sessions[0].session_id).toBe('session-1');
      expect(responseData.sessions[0].command_count).toBe(2);
      expect(responseData.sessions[1].session_id).toBe('session-2');
      expect(responseData.sessions[1].command_count).toBe(1);
    });

    it('should handle empty session list', async () => {
      mockSSHManager.listSessions = vi.fn().mockReturnValue([]);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_list_sessions']({}, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(true);
      expect(responseData.total_sessions).toBe(0);
      expect(responseData.sessions).toHaveLength(0);
    });
  });

  describe('close_session Handler', () => {
    it('should close session successfully', async () => {
      mockSSHManager.closeSession = vi.fn().mockResolvedValue(true);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_close_session']({
        session_id: 'session-to-close'
      }, toolContext);

      expect(mockSSHManager.closeSession).toHaveBeenCalledWith('session-to-close');

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        success: true,
        session_id: 'session-to-close',
        message: "Session 'session-to-close' closed successfully"
      });
    });

    it('should handle non-existent session', async () => {
      mockSSHManager.closeSession = vi.fn().mockResolvedValue(false);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_close_session']({
        session_id: 'non-existent'
      }, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        success: false,
        session_id: 'non-existent',
        message: "Session 'non-existent' not found"
      });
    });
  });

  describe('get_session_output Handler', () => {
    it('should get session output successfully', async () => {
      const mockSession = {
        getBufferedOutput: vi.fn().mockReturnValue(['line1\n', 'line2\n', 'line3\n'])
      };

      mockSSHManager.getSession = vi.fn().mockReturnValue(mockSession);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_get_session_output']({
        session_id: 'session-with-output'
      }, toolContext);

      expect(mockSSHManager.getSession).toHaveBeenCalledWith('session-with-output');
      expect(mockSession.getBufferedOutput).toHaveBeenCalledWith(undefined, false);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        success: true,
        session_id: 'session-with-output',
        output: 'line1\nline2\nline3\n',
        lines_returned: 3,
        buffer_cleared: false
      });
    });

    it('should handle line limit and clear buffer', async () => {
      const mockSession = {
        getBufferedOutput: vi.fn().mockReturnValue(['line1\n', 'line2\n'])
      };

      mockSSHManager.getSession = vi.fn().mockReturnValue(mockSession);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_get_session_output']({
        session_id: 'session-with-limit',
        lines: 2,
        clear: true
      }, toolContext);

      expect(mockSession.getBufferedOutput).toHaveBeenCalledWith(2, true);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.lines_returned).toBe(2);
      expect(responseData.buffer_cleared).toBe(true);
    });

    it('should handle non-existent session', async () => {
      mockSSHManager.getSession = vi.fn().mockReturnValue(undefined);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_get_session_output']({
        session_id: 'non-existent-session'
      }, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        success: false,
        session_id: 'non-existent-session',
        error: "Session 'non-existent-session' not found"
      });
    });
  });

  describe('close_all_sessions Handler', () => {
    it('should close all sessions successfully', async () => {
      const mockSessions = [
        { sessionId: 'session-1' },
        { sessionId: 'session-2' },
        { sessionId: 'session-3' }
      ];

      mockSSHManager.listSessions = vi.fn().mockReturnValue(mockSessions);
      mockSSHManager.disconnectAll = vi.fn().mockResolvedValue(undefined);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_close_all_sessions']({}, toolContext);

      expect(mockSSHManager.listSessions).toHaveBeenCalled();
      expect(mockSSHManager.disconnectAll).toHaveBeenCalled();

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        success: true,
        sessions_closed: 3,
        message: 'All 3 sessions have been closed'
      });
    });

    it('should handle empty session list', async () => {
      mockSSHManager.listSessions = vi.fn().mockReturnValue([]);
      mockSSHManager.disconnectAll = vi.fn().mockResolvedValue(undefined);

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_close_all_sessions']({}, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData).toEqual({
        success: true,
        sessions_closed: 0,
        message: 'All 0 sessions have been closed'
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle errors in session creation', async () => {
      mockSSHManager.createSession = vi.fn().mockRejectedValue(new Error('SSH connection failed'));

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_interactive_session']({}, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(false);
      expect(responseData.error).toBe('SSH connection failed');
    });

    it('should handle errors in session command execution', async () => {
      mockSSHManager.executeInSession = vi.fn().mockRejectedValue(new Error('Session not found'));

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_session_command']({
        session_id: 'invalid-session',
        command: 'test'
      }, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(false);
      expect(responseData.error).toBe('Session not found');
    });

    it('should handle getTargetCredentials errors', async () => {
      mockGetTargetCredentials.mockImplementation(() => {
        throw new Error('Target container not found');
      });

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_run_command']({ command: 'test' }, toolContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.success).toBe(false);
      expect(responseData.error).toBe('Target container not found');
    });
  });

  describe('Context Passing', () => {
    it('should pass context correctly to handlers', async () => {
      // Test that handlers receive the correct context
      const customContext = {
        sshManager: mockSSHManager,
        labConfig: {
          ...testLabConfig,
          server: {
            ...testLabConfig.server,
            targetName: 'Custom Target'
          }
        }
      };

      const handlers = generateToolHandlers(testLabConfig.server);
      const result = await handlers['test_info']({}, customContext);

      const responseData = JSON.parse(result.content[0].text);
      expect(responseData.target_name).toBe('Custom Target');
    });
  });

  describe('Backward Compatibility', () => {
    it('should export empty default toolHandlers for backward compatibility', () => {
      // This tests the export at the bottom of handlers.ts
      const { toolHandlers } = require('../../src/tools/handlers.js');
      expect(typeof toolHandlers).toBe('object');
      expect(Object.keys(toolHandlers)).toHaveLength(0);
    });
  });
});