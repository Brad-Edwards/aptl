import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { IncomingMessage, ClientRequest } from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Mock node:https before importing HTTPClient. Keep the real Agent
// constructor so we can introspect `options.ca` and `rejectUnauthorized`
// on the agent that the CA-aware path creates.
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

vi.mock('node:http', () => ({
  default: { request: vi.fn() },
}));

import https from 'node:https';
import { HTTPClient } from '../src/http.js';

const mockedHttpsRequest = vi.mocked(https.request);

function fakeResponse(statusCode: number, body: string): IncomingMessage {
  const res = new EventEmitter() as IncomingMessage;
  res.statusCode = statusCode;
  res.statusMessage = 'OK';
  process.nextTick(() => {
    res.emit('data', Buffer.from(body));
    res.emit('end');
  });
  return res;
}

function fakeRequest(): ClientRequest {
  const req = new EventEmitter() as ClientRequest;
  req.write = vi.fn(() => true) as any;
  req.end = vi.fn(() => req) as any;
  req.destroy = vi.fn() as any;
  return req;
}

// A short PEM-like blob — `https.Agent` does not parse the contents in
// the constructor, only stores them, so this is fine for unit tests.
const FAKE_CA_PEM = '-----BEGIN CERTIFICATE-----\nfakefakefakefake\n-----END CERTIFICATE-----\n';


describe('HTTPClient — SEC-006 CA-aware verification path', () => {
  let workdir: string;
  let caPath: string;

  beforeEach(() => {
    vi.clearAllMocks();
    workdir = mkdtempSync(join(tmpdir(), 'mcp-ca-test-'));
    caPath = join(workdir, 'lab-ca.pem');
    writeFileSync(caPath, FAKE_CA_PEM);
  });

  afterEach(() => {
    rmSync(workdir, { recursive: true, force: true });
  });

  function clientWith(opts: Partial<{ verify_ssl: boolean; ca_cert_path: string }> = {}) {
    return new HTTPClient({
      baseUrl: 'https://misp.lab:8443',
      auth: { type: 'apikey' as const, header: 'Authorization', apiKey: 'k' },
      verify_ssl: true,
      ...opts,
    });
  }

  it('uses node:https with the lab CA when verify_ssl=true and ca_cert_path is set', async () => {
    const res = fakeResponse(200, '{"ok":true}');
    const req = fakeRequest();
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = clientWith({ verify_ssl: true, ca_cert_path: caPath });
    const result = await client.makeRequest('/attributes/restSearch');

    expect(mockedHttpsRequest).toHaveBeenCalledTimes(1);
    expect(result.status).toBe(200);

    const opts = mockedHttpsRequest.mock.calls[0][0] as https.RequestOptions;
    // Agent is the CA-pinned per-instance one, NOT the insecureAgent.
    expect(opts.agent).toBeDefined();
    const agent = opts.agent as any;
    expect(agent.options.rejectUnauthorized).toBe(true);
    // The CA bundle was loaded from disk at HTTPClient construction.
    const ca = agent.options.ca;
    expect(ca).toBeDefined();
    expect(Buffer.isBuffer(ca) ? ca.toString() : String(ca)).toContain('BEGIN CERTIFICATE');
  });

  it('falls back to fetch() (system trust) when verify_ssl=true and no ca_cert_path', async () => {
    // Mock global fetch so we can assert it is used and node:https is not.
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('{"ok":true}', { status: 200, headers: { 'Content-Type': 'application/json' } })
    );
    (globalThis as any).fetch = fetchMock;

    const client = clientWith({ verify_ssl: true });
    const result = await client.makeRequest('/test');

    expect(result.status).toBe(200);
    // End-to-end body parsing: the fetch path must surface the
    // parsed JSON, not just the status code (a regression where
    // parseResponse swallowed the body would otherwise slip past
    // a status-only assertion).
    expect(result.data).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(mockedHttpsRequest).not.toHaveBeenCalled();
  });

  it('still uses the insecureAgent path when verify_ssl=false (SEC-004 unaffected)', async () => {
    const res = fakeResponse(200, '{"ok":true}');
    const req = fakeRequest();
    mockedHttpsRequest.mockImplementation((_opts: any, cb: any) => {
      cb(res);
      return req;
    });

    const client = clientWith({ verify_ssl: false, ca_cert_path: caPath });
    const result = await client.makeRequest('/test');

    expect(mockedHttpsRequest).toHaveBeenCalledTimes(1);
    const opts = mockedHttpsRequest.mock.calls[0][0] as https.RequestOptions;
    expect(opts.agent).toBeDefined();
    const agent = opts.agent as any;
    // verify_ssl=false ALWAYS wins — the CA-aware agent is bypassed.
    expect(agent.options.rejectUnauthorized).toBe(false);
    // The insecure path still has to parse and return the response
    // body. Status-code-only assertions miss parseBody regressions.
    expect(result.status).toBe(200);
    expect(result.data).toEqual({ ok: true });
  });

  it('throws at HTTPClient construction when ca_cert_path is set but unreadable', () => {
    // Path does not exist
    const missing = join(workdir, 'not-here.pem');
    expect(() =>
      new HTTPClient({
        baseUrl: 'https://misp.lab',
        auth: { type: 'apikey' as const, header: 'Authorization', apiKey: 'k' },
        verify_ssl: true,
        ca_cert_path: missing,
      })
    ).toThrow(/not readable/i);
  });

  it('does not throw when ca_cert_path is set but verify_ssl=false (CA agent simply not built)', () => {
    const missing = join(workdir, 'not-here.pem');
    // verify_ssl=false → the CA-aware path is never used, the missing
    // file should not crash the client.
    expect(() =>
      new HTTPClient({
        baseUrl: 'https://misp.lab',
        auth: { type: 'apikey' as const, header: 'Authorization', apiKey: 'k' },
        verify_ssl: false,
        ca_cert_path: missing,
      })
    ).not.toThrow();
  });
});
