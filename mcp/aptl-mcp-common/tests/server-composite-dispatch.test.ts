import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { CompositeContext, CompositeTool } from '../src/tools/composites.js';

// Capture the CallToolRequest handler registered by createMCPServer so the
// test can drive composite dispatch without a real MCP transport. Mirrors
// server-hook.test.ts.
let registeredHandlers: Array<(req: unknown) => unknown>;

vi.mock('@modelcontextprotocol/sdk/server/index.js', () => ({
  Server: vi.fn(function () {
    return {
      setRequestHandler: vi.fn((_schema: unknown, handler: (req: unknown) => unknown) => {
        registeredHandlers.push(handler);
      }),
      connect: vi.fn().mockResolvedValue(undefined),
    };
  }),
}));

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn(function () { return {}; }),
}));

vi.mock('../src/ssh.js', () => ({
  SSHConnectionManager: vi.fn(function () { return { __kind: 'ssh' }; }),
}));

vi.mock('../src/http.js', () => ({
  HTTPClient: vi.fn(function () { return { __kind: 'http' }; }),
}));

vi.mock('../src/telemetry.js', () => ({
  initTracing: vi.fn(),
  shutdownTracing: vi.fn().mockResolvedValue(undefined),
  getTracer: vi.fn(),
  traceToolCall: vi.fn(async (_n: unknown, _s: unknown, _a: unknown, fn: () => unknown) => fn()),
}));

const sshConfig = {
  version: '1.0.0',
  server: {
    name: 'test-server',
    version: '1.0.0',
    description: 'Test',
    toolPrefix: 'test',
    targetName: 'Test',
    configKey: 'test',
  },
  lab: { name: 'test-lab', network_subnet: '172.20.0.0/16' },
  containers: {
    test: { container_name: 't', container_ip: '127.0.0.1', ssh_key: '/k', ssh_user: 'u', ssh_port: 22, enabled: true },
  },
};

const apiConfig = {
  version: '1.0.0',
  server: { name: 'api-server', version: '1.0.0', description: 'Test', toolPrefix: 'test', targetName: 'Test', configKey: '' },
  lab: { name: 'test-lab', network_subnet: '172.20.0.0/16' },
  api: { baseUrl: 'https://localhost:9200', auth: { type: 'basic', username: 'u', password: 'p' } },
};

async function loadCreateMCPServer() {
  const mod = await import('../src/server.js');
  return mod.createMCPServer;
}

function makeComposite(overrides: Partial<CompositeTool>): CompositeTool {
  return {
    name: 'demo',
    description: 'demo',
    contextKind: 'ssh',
    inputSchema: { type: 'object', properties: {} },
    handler: vi.fn(async () => ({ content: [{ type: 'text', text: 'ok' }] })),
    ...overrides,
  };
}

describe('createMCPServer composite dispatch (ADR-045)', () => {
  beforeEach(() => {
    registeredHandlers = [];
    vi.clearAllMocks();
  });

  it('registers the composite under its prefixed name and lists it', async () => {
    const createMCPServer = await loadCreateMCPServer();
    createMCPServer(sshConfig as any, { composites: [makeComposite({ name: 'full_port_scan' })] });
    const listHandler = registeredHandlers[0];
    const listed = (await listHandler({})) as { tools: { name: string }[] };
    expect(listed.tools.some((t) => t.name === 'test_full_port_scan')).toBe(true);
  });

  it('routes an ssh composite with the SSH manager and no HTTP client', async () => {
    const handler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ok' }] }));
    const createMCPServer = await loadCreateMCPServer();
    createMCPServer(sshConfig as any, { composites: [makeComposite({ name: 'scan', contextKind: 'ssh', handler })] });
    const callHandler = registeredHandlers[1];
    await callHandler({ params: { name: 'test_scan', arguments: { target: '172.20.4.30' } } });
    expect(handler).toHaveBeenCalledTimes(1);
    const ctx = handler.mock.calls[0][1] as CompositeContext;
    expect(ctx.sshManager).toBeDefined();
    expect(ctx.httpClient).toBeUndefined();
    expect(ctx.labConfig).toBeDefined();
  });

  it('routes an api composite with the HTTP client and no SSH manager', async () => {
    const handler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ok' }] }));
    const createMCPServer = await loadCreateMCPServer();
    createMCPServer(apiConfig as any, { composites: [makeComposite({ name: 'report', contextKind: 'api', handler })] });
    const callHandler = registeredHandlers[1];
    await callHandler({ params: { name: 'test_report', arguments: {} } });
    const ctx = handler.mock.calls[0][1] as CompositeContext;
    expect(ctx.httpClient).toBeDefined();
    expect(ctx.sshManager).toBeUndefined();
  });

  it('throws when an ssh composite is dispatched on an api-only server', async () => {
    const createMCPServer = await loadCreateMCPServer();
    createMCPServer(apiConfig as any, { composites: [makeComposite({ name: 'scan', contextKind: 'ssh' })] });
    const callHandler = registeredHandlers[1];
    await expect(
      callHandler({ params: { name: 'test_scan', arguments: {} } }),
    ).rejects.toThrow(/SSH/);
  });

  it('fires the postToolHook exactly once for a composite call', async () => {
    const createMCPServer = await loadCreateMCPServer();
    const hook = vi.fn();
    createMCPServer(sshConfig as any, { composites: [makeComposite({ name: 'scan' })], postToolHook: hook });
    const callHandler = registeredHandlers[1];
    await callHandler({ params: { name: 'test_scan', arguments: { target: '172.20.4.30' } } });
    expect(hook).toHaveBeenCalledTimes(1);
    expect(hook.mock.calls[0][0].toolName).toBe('test_scan');
  });
});
