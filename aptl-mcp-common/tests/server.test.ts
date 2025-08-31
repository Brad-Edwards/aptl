import { describe, it, expect, vi } from 'vitest';
import { createMCPServer } from '../src/server.js';

// Mock dependencies
vi.mock('@modelcontextprotocol/sdk/server/index.js');
vi.mock('../src/ssh.js');
vi.mock('../src/tools/definitions.js');
vi.mock('../src/tools/handlers.js');

describe('createMCPServer', () => {
  const mockConfig = {
    server: {
      name: 'test-server',
      version: '1.0.0',
      description: 'Test Server - Description',
      toolPrefix: 'test',
      targetName: 'Test Container',
      configKey: 'test-container',
      envPrefix: 'APTL_TEST'
    },
    lab: {
      name: 'test-lab',
      network_subnet: '172.20.0.0/16'
    },
    containers: {
      'test-container': {
        container_name: 'test',
        container_ip: 'localhost',
        ssh_key: '/path/to/key',
        ssh_user: 'testuser',
        ssh_port: 22,
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

  it('creates server with config', () => {
    const server = createMCPServer(mockConfig);
    expect(server).toBeDefined();
    expect(server.start).toBeDefined();
  });

  it('generates tools using server config', () => {
    const { generateToolDefinitions } = vi.mocked(await import('../src/tools/definitions.js'));
    generateToolDefinitions.mockReturnValue([]);
    
    createMCPServer(mockConfig);
    
    expect(generateToolDefinitions).toHaveBeenCalledWith(mockConfig.server);
  });

  it('generates handlers using server config', () => {
    const { generateToolHandlers } = vi.mocked(await import('../src/tools/handlers.js'));
    generateToolHandlers.mockReturnValue({});
    
    createMCPServer(mockConfig);
    
    expect(generateToolHandlers).toHaveBeenCalledWith(mockConfig.server);
  });
});