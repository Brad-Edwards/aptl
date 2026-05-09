import { describe, it, expect, vi, beforeEach } from 'vitest';

// Capture the CallToolRequest handler registered by createMCPServer so the
// test can drive it without a real MCP transport. Mock factories must be
// declared at module scope (vi.mock is hoisted).
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
  SSHConnectionManager: vi.fn(function () { return {}; }),
}));

vi.mock('../src/telemetry.js', () => ({
  initTracing: vi.fn(),
  shutdownTracing: vi.fn().mockResolvedValue(undefined),
  getTracer: vi.fn(),
  // Pass-through: invoke the handler immediately, no real OTel span machinery.
  traceToolCall: vi.fn(async (_n: unknown, _s: unknown, _a: unknown, fn: () => unknown) => fn()),
}));

const baseConfig = {
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
    test: {
      container_name: 't',
      container_ip: '127.0.0.1',
      ssh_key: '/k',
      ssh_user: 'u',
      ssh_port: 22,
      enabled: true,
    },
  },
};

async function loadCreateMCPServer() {
  const mod = await import('../src/server.js');
  return mod.createMCPServer;
}

describe('createMCPServer postToolHook', () => {
  beforeEach(() => {
    registeredHandlers = [];
    vi.clearAllMocks();
  });

  it('invokes the hook after a successful tool call with toolName, args, result and durationMs', async () => {
    const handlersMod = await import('../src/tools/handlers.js');
    const handlerResult = { content: [{ type: 'text', text: '{"success":true}' }] };
    vi.spyOn(handlersMod, 'generateToolHandlers').mockReturnValue({
      test_run_command: vi.fn().mockResolvedValue(handlerResult),
    } as any);
    const defsMod = await import('../src/tools/definitions.js');
    vi.spyOn(defsMod, 'generateToolDefinitions').mockReturnValue([]);

    const createMCPServer = await loadCreateMCPServer();
    const hook = vi.fn();
    createMCPServer(baseConfig as any, { postToolHook: hook });

    // server.ts registers ListTools first, then CallTool — the call handler is the second.
    const callHandler = registeredHandlers[1];
    const result = await callHandler({
      params: { name: 'test_run_command', arguments: { command: 'ls -la' } },
    });

    expect(result).toBe(handlerResult);
    expect(hook).toHaveBeenCalledTimes(1);
    const info = hook.mock.calls[0][0];
    expect(info.toolName).toBe('test_run_command');
    expect(info.args).toEqual({ command: 'ls -la' });
    expect(info.result).toBe(handlerResult);
    expect(typeof info.durationMs).toBe('number');
    expect(info.durationMs).toBeGreaterThanOrEqual(0);
    expect(info.error).toBeUndefined();
  });

  it('invokes the hook with the error when the handler throws and re-throws to the caller', async () => {
    const handlersMod = await import('../src/tools/handlers.js');
    const boom = new Error('handler exploded');
    vi.spyOn(handlersMod, 'generateToolHandlers').mockReturnValue({
      test_run_command: vi.fn().mockRejectedValue(boom),
    } as any);
    const defsMod = await import('../src/tools/definitions.js');
    vi.spyOn(defsMod, 'generateToolDefinitions').mockReturnValue([]);

    const createMCPServer = await loadCreateMCPServer();
    const hook = vi.fn();
    createMCPServer(baseConfig as any, { postToolHook: hook });

    const callHandler = registeredHandlers[1];
    await expect(
      callHandler({ params: { name: 'test_run_command', arguments: { command: 'x' } } }),
    ).rejects.toBe(boom);

    expect(hook).toHaveBeenCalledTimes(1);
    const info = hook.mock.calls[0][0];
    expect(info.toolName).toBe('test_run_command');
    expect(info.error).toBe(boom);
    expect(info.result).toBeUndefined();
  });

  it('catches a hook that throws so the tool result is returned unchanged', async () => {
    const handlersMod = await import('../src/tools/handlers.js');
    const handlerResult = { content: [{ type: 'text', text: 'ok' }] };
    vi.spyOn(handlersMod, 'generateToolHandlers').mockReturnValue({
      test_run_command: vi.fn().mockResolvedValue(handlerResult),
    } as any);
    const defsMod = await import('../src/tools/definitions.js');
    vi.spyOn(defsMod, 'generateToolDefinitions').mockReturnValue([]);

    const createMCPServer = await loadCreateMCPServer();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const hook = vi.fn(() => {
      throw new Error('hook is buggy');
    });
    createMCPServer(baseConfig as any, { postToolHook: hook });

    const callHandler = registeredHandlers[1];
    const result = await callHandler({
      params: { name: 'test_run_command', arguments: {} },
    });

    expect(result).toBe(handlerResult);
    // Fire-and-forget: error logs land on a microtask after the
    // response resolves. Flush microtasks before asserting.
    await new Promise((r) => setImmediate(r));
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('catches an async hook rejection without propagating to the caller (cycle-5 review)', async () => {
    const handlersMod = await import('../src/tools/handlers.js');
    const handlerResult = { content: [{ type: 'text', text: 'ok' }] };
    vi.spyOn(handlersMod, 'generateToolHandlers').mockReturnValue({
      test_run_command: vi.fn().mockResolvedValue(handlerResult),
    } as any);
    const defsMod = await import('../src/tools/definitions.js');
    vi.spyOn(defsMod, 'generateToolDefinitions').mockReturnValue([]);

    const createMCPServer = await loadCreateMCPServer();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    // The hook returns a promise that rejects asynchronously. The server
    // must await it inside its try/catch — otherwise the rejection becomes
    // an unhandled rejection and the documented best-effort error log is
    // never emitted.
    const hook = vi.fn(async () => {
      throw new Error('async sink rejected');
    });
    createMCPServer(baseConfig as any, { postToolHook: hook });
    const callHandler = registeredHandlers[1];
    const result = await callHandler({
      params: { name: 'test_run_command', arguments: {} },
    });
    expect(result).toBe(handlerResult);
    expect(hook).toHaveBeenCalledTimes(1);
    // Fire-and-forget: rejection flows into console.error on a later
    // microtask. Flush microtasks before checking.
    await new Promise((r) => setImmediate(r));
    expect(errorSpy).toHaveBeenCalled();
    const loggedAny = errorSpy.mock.calls.some((args) =>
      args.some((arg) => /async sink rejected/.test(String((arg as Error)?.message ?? arg))),
    );
    expect(loggedAny).toBe(true);
    errorSpy.mockRestore();
  });

  it('returns the tool result without waiting for an async hook to resolve (cycle-11 review)', async () => {
    const handlersMod = await import('../src/tools/handlers.js');
    const handlerResult = { content: [{ type: 'text', text: 'ok' }] };
    vi.spyOn(handlersMod, 'generateToolHandlers').mockReturnValue({
      test_run_command: vi.fn().mockResolvedValue(handlerResult),
    } as any);
    const defsMod = await import('../src/tools/definitions.js');
    vi.spyOn(defsMod, 'generateToolDefinitions').mockReturnValue([]);

    const createMCPServer = await loadCreateMCPServer();
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    // Deterministic timing test: the hook returns a promise that
    // resolves only when WE choose; the assertion is that the response
    // resolves BEFORE we resolve the hook. No wall-clock thresholds
    // (which are flaky on loaded CI runners).
    let hookResolved = false;
    let resolveHook: (() => void) | undefined;
    const hookPromise = new Promise<void>((r) => {
      resolveHook = () => {
        hookResolved = true;
        r();
      };
    });
    const hookCalled = vi.fn(() => hookPromise);
    createMCPServer(baseConfig as any, {
      postToolHook: hookCalled,
      postToolHookTimeoutMs: 50,
    });
    const callHandler = registeredHandlers[1];
    const result = await callHandler({
      params: { name: 'test_run_command', arguments: {} },
    });
    // The response must resolve before the hook resolves.
    expect(result).toBe(handlerResult);
    expect(hookResolved).toBe(false);
    expect(hookCalled).toHaveBeenCalledTimes(1);
    // Now let the hook timeout fire — wait long enough that a 50ms
    // race-rejection has surfaced through the .catch wrapper.
    await new Promise((r) => setTimeout(r, 120));
    expect(errorSpy).toHaveBeenCalled();
    // Cleanup: resolve the hook so the never-pending promise can be GC'd.
    resolveHook?.();
    errorSpy.mockRestore();
  });

  it('does not require a hook (existing call sites still work)', async () => {
    const handlersMod = await import('../src/tools/handlers.js');
    const handlerResult = { content: [{ type: 'text', text: 'ok' }] };
    vi.spyOn(handlersMod, 'generateToolHandlers').mockReturnValue({
      test_run_command: vi.fn().mockResolvedValue(handlerResult),
    } as any);
    const defsMod = await import('../src/tools/definitions.js');
    vi.spyOn(defsMod, 'generateToolDefinitions').mockReturnValue([]);

    const createMCPServer = await loadCreateMCPServer();
    createMCPServer(baseConfig as any);
    const callHandler = registeredHandlers[1];
    const result = await callHandler({
      params: { name: 'test_run_command', arguments: {} },
    });
    expect(result).toBe(handlerResult);
  });
});
