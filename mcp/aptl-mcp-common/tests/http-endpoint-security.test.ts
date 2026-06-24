import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HTTPClient } from '../src/http.js';
import { generateAPIToolHandlers } from '../src/tools/api-handlers.js';
import type { LabConfig } from '../src/config.js';

global.fetch = vi.fn();

describe('HTTPClient endpoint origin scoping', () => {
  const mockFetch = vi.mocked(global.fetch);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects cross-origin absolute URLs before attaching auth', async () => {
    const client = new HTTPClient({
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'secret-token' },
    });

    await expect(client.makeRequest('https://attacker.example/collect')).rejects.toThrow(
      'does not match configured API origin',
    );
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('does not send auth to cross-origin destinations via path traversal tricks', async () => {
    const client = new HTTPClient({
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'secret-token' },
    });

    await expect(client.makeRequest('//attacker.example/collect')).rejects.toThrow(
      'does not match configured API origin',
    );
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('still attaches auth for same-origin path requests', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{}'),
    } as any);

    const client = new HTTPClient({
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'secret-token' },
    });

    await client.makeRequest('/alerts');

    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.example.com/alerts',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer secret-token',
        }),
      }),
    );
  });
});

describe('generic api_call handler', () => {
  const labConfig = {
    server: { toolPrefix: 'test', targetName: 'Test API' },
    lab: { name: 'lab', network_subnet: '10.0.0.0/24' },
    api: {
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'secret-token' },
    },
  } as LabConfig;

  it('returns success false for absolute URL endpoints', async () => {
    const handlers = generateAPIToolHandlers(labConfig.server, undefined, true);
    const httpClient = {
      makeRequest: vi.fn(),
    } as unknown as HTTPClient;

    const result = await handlers.test_api_call(
      { endpoint: 'https://attacker.example/collect' },
      { httpClient, labConfig },
    );

    const payload = JSON.parse(result.content[0].text);
    expect(payload.success).toBe(false);
    expect(payload.error).toContain('endpoint must be a path starting with /');
    expect(httpClient.makeRequest).not.toHaveBeenCalled();
  });
});
