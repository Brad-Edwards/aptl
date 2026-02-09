import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { IncomingMessage, ClientRequest } from 'node:http';

// Mock node:https before importing HTTPClient
vi.mock('node:https', () => {
  const { Agent } = require('node:https');
  return {
    default: {
      Agent,
      request: vi.fn(),
    },
    Agent,
  };
});

// Also mock node:http for the transport fallback
vi.mock('node:http', () => ({
  default: {
    request: vi.fn(),
  },
}));

import https from 'node:https';
import http from 'node:http';
import { HTTPClient } from '../src/http.js';

const mockedHttpsRequest = vi.mocked(https.request);
const mockedHttpRequest = vi.mocked(http.request);

/** Helper: create a fake IncomingMessage that emits data+end */
function fakeResponse(statusCode: number, body: string, statusMessage = 'OK'): IncomingMessage {
  const res = new EventEmitter() as IncomingMessage;
  res.statusCode = statusCode;
  res.statusMessage = statusMessage;
  // Simulate async data delivery
  process.nextTick(() => {
    res.emit('data', Buffer.from(body));
    res.emit('end');
  });
  return res;
}

/** Helper: create a fake ClientRequest that captures writes */
function fakeRequest(response: IncomingMessage): ClientRequest & { writtenData: string[] } {
  const req = new EventEmitter() as ClientRequest & { writtenData: string[] };
  req.writtenData = [];
  req.write = vi.fn((data: any) => {
    req.writtenData.push(String(data));
    return true;
  }) as any;
  req.end = vi.fn(() => {
    // Emit the response via the callback passed to transport.request
    return req;
  }) as any;
  req.destroy = vi.fn() as any;
  return req;
}

describe('HTTPClient — verify_ssl=false path', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function createClient(overrides = {}) {
    return new HTTPClient({
      baseUrl: 'https://wazuh.local:9200',
      auth: { type: 'basic' as const, username: 'admin', password: 'admin' },
      verify_ssl: false,
      ...overrides,
    });
  }

  it('uses node:https transport when verify_ssl is false', async () => {
    const res = fakeResponse(200, '{"status":"ok"}');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    const result = await client.makeRequest('/test');

    expect(mockedHttpsRequest).toHaveBeenCalledTimes(1);
    expect(result.status).toBe(200);
    expect(result.data).toEqual({ status: 'ok' });
  });

  it('passes insecure agent in request options', async () => {
    const res = fakeResponse(200, '{}');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    await client.makeRequest('/test');

    const opts = mockedHttpsRequest.mock.calls[0][0] as any;
    expect(opts.agent).toBeDefined();
    expect(opts.agent.options.rejectUnauthorized).toBe(false);
  });

  it('sets Content-Length header when body is provided', async () => {
    const res = fakeResponse(200, '{}');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    const body = { query: { match_all: {} } };
    await client.makeRequest('/search', 'POST', { body });

    const opts = mockedHttpsRequest.mock.calls[0][0] as any;
    const bodyStr = JSON.stringify(body);
    expect(opts.headers['Content-Length']).toBe(String(Buffer.byteLength(bodyStr)));
  });

  it('does not set Content-Length when no body', async () => {
    const res = fakeResponse(200, '{}');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    await client.makeRequest('/test');

    const opts = mockedHttpsRequest.mock.calls[0][0] as any;
    expect(opts.headers['Content-Length']).toBeUndefined();
  });

  it('writes serialized body to request', async () => {
    const res = fakeResponse(200, '{}');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    const body = { index: 'wazuh-alerts' };
    await client.makeRequest('/search', 'POST', { body });

    expect(req.write).toHaveBeenCalledWith(JSON.stringify(body));
  });

  it('rejects with HTTPError on non-2xx status', async () => {
    const res = fakeResponse(401, '{"error":"unauthorized"}', 'Unauthorized');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    await expect(client.makeRequest('/secure')).rejects.toThrow('HTTP 401: Unauthorized');
  });

  it('returns text as data when responseType is text', async () => {
    const res = fakeResponse(200, 'plain text response');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    const result = await client.makeRequest('/text', 'GET', { responseType: 'text' });

    expect(result.data).toBe('plain text response');
    expect(result.text).toBe('plain text response');
  });

  it('falls back to text when JSON parsing fails', async () => {
    const res = fakeResponse(200, 'not json');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    const result = await client.makeRequest('/bad-json');

    expect(result.data).toBe('not json');
  });

  it('builds correct URL from baseUrl + endpoint', async () => {
    const res = fakeResponse(200, '{}');
    const req = fakeRequest(res);
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = createClient();
    await client.makeRequest('/api/v1/alerts');

    const opts = mockedHttpsRequest.mock.calls[0][0] as any;
    expect(opts.hostname).toBe('wazuh.local');
    expect(opts.port).toBe('9200');
    expect(opts.path).toBe('/api/v1/alerts');
  });
});

describe('HTTPClient — verify_ssl=true path (fetch)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  it('uses fetch when verify_ssl is true (default)', async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: () => Promise.resolve('{"result":"ok"}'),
    } as any);

    const client = new HTTPClient({
      baseUrl: 'https://api.example.com',
      auth: { type: 'basic' as const, username: 'u', password: 'p' },
    });
    await client.makeRequest('/test');

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockedHttpsRequest).not.toHaveBeenCalled();
  });
});
