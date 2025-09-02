import { describe, it, expect, vi } from 'vitest';
import { generateToolHandlers } from '../src/tools/handlers.js';

// Mock SSH manager
vi.mock('../src/ssh.js');

describe('generateToolHandlers', () => {
  const mockServerConfig = {
    toolPrefix: 'test',
    targetName: 'Test Container',
    configKey: 'test-container'
  };

  it('generates handler map with correct tool names', () => {
    const handlers = generateToolHandlers(mockServerConfig);
    
    expect(handlers['test_info']).toBeDefined();
    expect(handlers['test_run_command']).toBeDefined();
    expect(handlers['test_interactive_session']).toBeDefined();
    expect(handlers['test_background_session']).toBeDefined();
    expect(handlers['test_session_command']).toBeDefined();
    expect(handlers['test_list_sessions']).toBeDefined();
    expect(handlers['test_close_session']).toBeDefined();
    expect(handlers['test_get_session_output']).toBeDefined();
    expect(handlers['test_close_all_sessions']).toBeDefined();
  });

  it('works with different server configs', () => {
    const kaliConfig = {
      toolPrefix: 'kali',
      targetName: 'Kali Linux',
      configKey: 'kali'
    };
    
    const handlers = generateToolHandlers(kaliConfig);
    
    expect(handlers['kali_info']).toBeDefined();
    expect(handlers['kali_run_command']).toBeDefined();
  });

  it('generates all expected handlers', () => {
    const handlers = generateToolHandlers(mockServerConfig);
    expect(Object.keys(handlers)).toHaveLength(9);
  });

  it('all handlers are functions', () => {
    const handlers = generateToolHandlers(mockServerConfig);
    Object.values(handlers).forEach(handler => {
      expect(typeof handler).toBe('function');
    });
  });

  it('handles empty toolPrefix', () => {
    const emptyConfig = {
      toolPrefix: '',
      targetName: 'Test',
      configKey: 'test'
    };
    
    const handlers = generateToolHandlers(emptyConfig);
    expect(handlers['_info']).toBeDefined();
    expect(handlers['_run_command']).toBeDefined();
  });
});

describe('handler execution logic', () => {
  const mockLabConfig = {
    server: {
      configKey: 'test-container',
      targetName: 'Test Container'
    },
    lab: {
      name: 'test-lab',
      network_subnet: '172.20.0.0/16'
    },
    containers: {
      'test-container': {
        container_ip: '172.20.0.50',
        ssh_user: 'testuser',
        ssh_port: 2022,
        enabled: true
      }
    }
  };

  const mockContext = {
    sshManager: {},
    labConfig: mockLabConfig
  };

  it('target_info returns container info when enabled', async () => {
    const handlers = generateToolHandlers({ toolPrefix: 'test', targetName: 'Test', configKey: 'test-container' });
    const result = await handlers['test_info']({}, mockContext);
    
    expect(result.content[0].text).toContain('172.20.0.50');
    expect(result.content[0].text).toContain('testuser');
    expect(result.content[0].text).toContain('test-lab');
  });

  it('target_info returns error when container disabled', async () => {
    const disabledConfig = {
      ...mockLabConfig,
      containers: {
        'test-container': {
          ...mockLabConfig.containers['test-container'],
          enabled: false
        }
      }
    };
    
    const disabledContext = { ...mockContext, labConfig: disabledConfig };
    const handlers = generateToolHandlers({ toolPrefix: 'test', targetName: 'Test Container', configKey: 'test-container' });
    
    const result = await handlers['test_info']({}, disabledContext);
    expect(result.content[0].text).toContain('not enabled');
  });
});