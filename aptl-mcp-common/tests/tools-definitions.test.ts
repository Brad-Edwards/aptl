import { describe, it, expect } from 'vitest';
import { generateToolDefinitions } from '../src/tools/definitions.js';

describe('generateToolDefinitions', () => {
  const mockServerConfig = {
    toolPrefix: 'test',
    targetName: 'Test Container'
  };

  it('generates tools with correct names using toolPrefix', () => {
    const tools = generateToolDefinitions(mockServerConfig);
    
    expect(tools[0].name).toBe('test_info');
    expect(tools[1].name).toBe('test_run_command');
    expect(tools[2].name).toBe('test_interactive_session');
    expect(tools[3].name).toBe('test_background_session');
    expect(tools[4].name).toBe('test_session_command');
    expect(tools[5].name).toBe('test_list_sessions');
    expect(tools[6].name).toBe('test_close_session');
    expect(tools[7].name).toBe('test_get_session_output');
    expect(tools[8].name).toBe('test_close_all_sessions');
  });

  it('generates descriptions using targetName', () => {
    const tools = generateToolDefinitions(mockServerConfig);
    
    expect(tools[0].description).toContain('Test Container');
    expect(tools[1].description).toContain('Test Container');
  });

  it('generates expected number of tools', () => {
    const tools = generateToolDefinitions(mockServerConfig);
    expect(tools).toHaveLength(9);
  });

  it('works with different server configs', () => {
    const kaliConfig = {
      toolPrefix: 'kali',
      targetName: 'Kali Linux'
    };
    
    const tools = generateToolDefinitions(kaliConfig);
    
    expect(tools[0].name).toBe('kali_info');
    expect(tools[1].name).toBe('kali_run_command');
    expect(tools[0].description).toContain('Kali Linux');
  });
});