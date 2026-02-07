import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock all dependencies — use function() form so they work with `new`
vi.mock('@modelcontextprotocol/sdk/server/index.js', () => ({
  Server: vi.fn(function () {
    return {
      setRequestHandler: vi.fn(),
      connect: vi.fn().mockResolvedValue(undefined)
    };
  })
}));

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn(function () { return {}; })
}));

vi.mock('../src/ssh.js', () => ({
  SSHConnectionManager: vi.fn(function () { return {}; })
}));

vi.mock('../src/tools/definitions.js', () => ({
  generateToolDefinitions: vi.fn().mockReturnValue([])
}));

vi.mock('../src/tools/handlers.js', () => ({
  generateToolHandlers: vi.fn().mockReturnValue({})
}));

describe('createMCPServer', () => {
  let createMCPServer: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    const module = await import('../src/server.js');
    createMCPServer = module.createMCPServer;
  });

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

  it('creates server with valid config', () => {
    const server = createMCPServer(mockConfig);
    expect(server).toBeDefined();
    expect(server.start).toBeDefined();
    expect(typeof server.start).toBe('function');
  });

  it('calls tool generation functions', async () => {
    const definitions = await import('../src/tools/definitions.js');
    const handlers = await import('../src/tools/handlers.js');
    const mockGenDefs = vi.spyOn(definitions, 'generateToolDefinitions').mockReturnValue([]);
    const mockGenHandlers = vi.spyOn(handlers, 'generateToolHandlers').mockReturnValue({});
    
    createMCPServer(mockConfig);
    
    expect(mockGenDefs).toHaveBeenCalledWith(mockConfig.server);
    expect(mockGenHandlers).toHaveBeenCalledWith(mockConfig.server);
  });

  it('creates SSH manager', async () => {
    const ssh = await import('../src/ssh.js');
    const mockSSH = vi.spyOn(ssh, 'SSHConnectionManager');
    
    createMCPServer(mockConfig);
    
    expect(mockSSH).toHaveBeenCalled();
  });

  it('works with different server configs', () => {
    const kaliConfig = {
      ...mockConfig,
      server: {
        ...mockConfig.server,
        name: 'kali-server',
        toolPrefix: 'kali',
        targetName: 'Kali Linux'
      }
    };
    
    const server = createMCPServer(kaliConfig);
    expect(server).toBeDefined();
  });
});