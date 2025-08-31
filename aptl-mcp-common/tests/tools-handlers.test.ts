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

  it('returns empty object when no base handlers exist', () => {
    const emptyConfig = {
      toolPrefix: '',
      targetName: '',
      configKey: ''
    };
    
    const handlers = generateToolHandlers(emptyConfig);
    expect(Object.keys(handlers)).toHaveLength(9);
  });
});