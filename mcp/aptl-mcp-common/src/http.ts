import https from 'node:https';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { LabConfig } from './config.js';

export interface HTTPError extends Error {
  statusCode?: number;
  response?: any;
}

export interface HTTPResponse {
  ok: boolean;
  status: number;
  data: any;
  text: string;
}

// Per-instance HTTPS agent that skips SSL verification, avoiding process-global mutation
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

/**
 * Generic HTTP client for API operations
 */
export class HTTPClient {
  // SEC-006 / ADR-034: per-instance CA-aware agent. Built lazily once at
  // construction when `verify_ssl=true` AND `ca_cert_path` is set. Cached
  // here so the CA file is read once per HTTPClient, not per request.
  // `null` means "no custom CA — fall back to fetch() with system trust";
  // an instantiated Agent means "use node:https with this CA, rejectUnauthorized=true".
  private readonly caAgent: https.Agent | null;

  constructor(private config: LabConfig['api']) {
    if (!config) {
      throw new Error('API configuration is required');
    }
    this.caAgent = buildCaAgent(config);
  }

  // cached JWT for wazuh-jwt mode (per HTTPClient instance)
  private cachedJwt: string | null = null;

  /**
   * Build authentication headers based on config (sync paths only).
   * For 'wazuh-jwt' use getAuthHeadersAsync.
   */
  private buildAuthHeaders(): Record<string, string> {
    const { auth } = this.config!;

    switch (auth.type) {
      case 'basic':
        if (!auth.username || !auth.password) {
          throw new Error('Username and password required for basic auth');
        }
        const basicAuth = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
        return { 'Authorization': `Basic ${basicAuth}` };

      case 'bearer':
        if (!auth.token) {
          throw new Error('Token required for bearer auth');
        }
        return { 'Authorization': `Bearer ${auth.token}` };

      case 'apikey':
        if (!auth.apiKey || !auth.header) {
          throw new Error('API key and header name required for API key auth');
        }
        return { [auth.header]: auth.apiKey };

      case 'custom':
        if (!auth.header || !auth.token) {
          throw new Error('Header name and token required for custom auth');
        }
        return { [auth.header]: auth.token };

      case 'wazuh-jwt':
        if (this.cachedJwt) {
          return { 'Authorization': `Bearer ${this.cachedJwt}` };
        }
        // Should have been exchanged before sync call; placeholder so auth runs anyway
        return {};

      default:
        return {};
    }
  }

  /**
   * Async-aware auth header builder. For 'wazuh-jwt' mode, performs a one-time
   * POST {auth_url} with basic credentials, caches the returned JWT, and
   * returns a Bearer header. Subsequent calls reuse the cached token.
   */
  private async getAuthHeadersAsync(): Promise<Record<string, string>> {
    const { auth } = this.config!;
    if (auth.type !== 'wazuh-jwt') return this.buildAuthHeaders();

    if (this.cachedJwt) {
      return { 'Authorization': `Bearer ${this.cachedJwt}` };
    }

    if (!auth.username || !auth.password || !auth.auth_url) {
      throw new Error('wazuh-jwt requires username, password, auth_url');
    }

    const basicAuth = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
    const verify_ssl = this.config!.verify_ssl !== false; // default true
    const tokenResp = await this.lowLevelRequest(
      auth.auth_url,
      'POST',
      { 'Authorization': `Basic ${basicAuth}` },
      undefined,
      this.config!.timeout || 30000,
      verify_ssl
    );
    let parsed: any;
    try { parsed = JSON.parse(tokenResp.text); } catch { parsed = {}; }
    const token = parsed?.data?.token;
    if (!token) {
      throw new Error(`wazuh-jwt: no token in auth response (status ${tokenResp.status})`);
    }
    this.cachedJwt = token;
    return { 'Authorization': `Bearer ${token}` };
  }

  /**
   * Low-level helper used by the JWT exchange path. Does not apply auth.
   */
  private lowLevelRequest(
    url: string,
    method: string,
    headers: Record<string, string>,
    body: string | undefined,
    timeout: number,
    verify_ssl: boolean
  ): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const transport = parsed.protocol === 'https:' ? https : http;
      const reqOpts: https.RequestOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          ...headers,
          ...(body ? { 'Content-Length': String(Buffer.byteLength(body)) } : {}),
        },
        timeout,
        ...(parsed.protocol === 'https:'
          ? this.resolveHttpsAgentOpts(verify_ssl)
          : {}),
      };
      const req = transport.request(reqOpts, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({
          status: res.statusCode ?? 0,
          text: Buffer.concat(chunks).toString(),
        }));
      });
      req.on('timeout', () => { req.destroy(); reject(new Error(`token timeout after ${timeout}ms`)); });
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  }

  /**
   * Make HTTP request with automatic auth and error handling
   */
  async makeRequest(
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
    options: {
      params?: Record<string, any>;
      body?: any;
      headers?: Record<string, string>;
      responseType?: 'json' | 'text';
    } = {}
  ): Promise<HTTPResponse> {
    const { baseUrl, timeout = 30000, verify_ssl = true, default_headers = {} } = this.config!;

    // Build URL with params - handle both full URLs and endpoint paths
    let url = endpoint.startsWith('http') ? endpoint : `${baseUrl}${endpoint}`;
    if (options.params) {
      const searchParams = new URLSearchParams();
      Object.entries(options.params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          searchParams.append(key, String(value));
        }
      });
      if (searchParams.toString()) {
        url += `?${searchParams.toString()}`;
      }
    }

    // Build headers (await for wazuh-jwt path, no-op for others)
    const authHeaders = await this.getAuthHeadersAsync();
    const headers = {
      'Content-Type': 'application/json',
      ...default_headers,
      ...authHeaders,
      ...options.headers,
    };

    // String body passes through raw (e.g. XML for Wazuh rule upload). Set
    // Content-Type to octet-stream unless caller already set one.
    let bodyStr: string | undefined;
    if (options.body !== undefined && options.body !== null) {
      if (typeof options.body === 'string') {
        bodyStr = options.body;
        if (!('Content-Type' in (options.headers || {}))) {
          headers['Content-Type'] = 'application/octet-stream';
        }
      } else {
        bodyStr = JSON.stringify(options.body);
      }
    }

    // SEC-006 / ADR-034: Node's `fetch` cannot accept a custom CA bundle.
    // Three-state TLS policy:
    //  1. verify_ssl=false → node:https with insecureAgent (existing SEC-004 path).
    //  2. verify_ssl=true + ca_cert_path set → node:https with the CA-aware
    //     agent built once at construction (`this.caAgent`).
    //  3. verify_ssl=true + no CA path → fetch() with system trust (legacy).
    if (!verify_ssl || this.caAgent) {
      return this.makeRequestWithAgent(url, method, headers, { ...options, body: bodyStr } as any, timeout, verify_ssl);
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method,
        headers,
        body: bodyStr,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      return this.parseResponse(response, options.responseType);
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }
      throw error;
    }
  }

  /**
   * Parse response body text into data, falling back to raw text on JSON errors.
   */
  private parseBody(text: string, responseType?: 'json' | 'text'): any {
    if (responseType === 'text') return text;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  /**
   * Build an HTTPError from a status code, status text, and parsed body.
   */
  private buildHTTPError(status: number, statusText: string, body: any): HTTPError {
    const error = new Error(`HTTP ${status}: ${statusText}`) as HTTPError;
    error.statusCode = status;
    error.response = body;
    return error;
  }

  /**
   * Make HTTP request using node:https with a per-request agent.
   *
   * SEC-006 / ADR-034: this path now serves two cases — the SEC-004
   * insecure path (``verify_ssl=false``) AND the CA-pinned path
   * (``verify_ssl=true`` + ``ca_cert_path`` set). The right agent is
   * resolved per call from ``this.caAgent`` + ``verify_ssl``.
   */
  private makeRequestWithAgent(
    url: string,
    method: string,
    headers: Record<string, string>,
    options: { body?: any; responseType?: 'json' | 'text' },
    timeout: number,
    verify_ssl: boolean = false
  ): Promise<HTTPResponse> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const transport = parsed.protocol === 'https:' ? https : http;
      // body may already be a pre-stringified raw payload (XML / JSON) at this point
      const bodyStr: string | undefined = options.body === undefined || options.body === null
        ? undefined
        : (typeof options.body === 'string' ? options.body : JSON.stringify(options.body));

      const reqOptions: https.RequestOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          ...headers,
          ...(bodyStr ? { 'Content-Length': String(Buffer.byteLength(bodyStr)) } : {}),
        },
        timeout,
        ...(parsed.protocol === 'https:'
          ? this.resolveHttpsAgentOpts(verify_ssl)
          : {}),
      };

      const req = transport.request(reqOptions, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const responseText = Buffer.concat(chunks).toString();
          const responseData = this.parseBody(responseText, options.responseType);
          const status = res.statusCode ?? 0;
          const ok = status >= 200 && status < 300;

          if (!ok) {
            reject(this.buildHTTPError(status, res.statusMessage ?? '', responseData));
            return;
          }

          resolve({ ok, status, data: responseData, text: responseText });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timeout after ${timeout}ms`));
      });

      req.on('error', (error) => {
        reject(error);
      });

      if (bodyStr) {
        req.write(bodyStr);
      }
      req.end();
    });
  }

  /**
   * Resolve the per-request agent options for an HTTPS URL.
   *
   * Three-state policy (SEC-006 / ADR-034):
   *  - verify_ssl=false → process-safe ``insecureAgent`` (SEC-004 path).
   *  - verify_ssl=true + CA configured → the per-instance CA-aware agent.
   *  - verify_ssl=true + no CA → ``{}`` so Node falls back to its default
   *    HTTPS agent with system trust (the existing fetch() path covers this
   *    case at the call sites; this branch is here for the JWT exchange's
   *    ``lowLevelRequest`` path which always goes through node:https).
   */
  private resolveHttpsAgentOpts(verify_ssl: boolean): { agent?: https.Agent } {
    if (!verify_ssl) return { agent: insecureAgent };
    if (this.caAgent) return { agent: this.caAgent };
    return {};
  }

  /**
   * Parse a fetch Response into our HTTPResponse format
   */
  private async parseResponse(
    response: Response,
    responseType?: 'json' | 'text'
  ): Promise<HTTPResponse> {
    const responseText = await response.text();
    const responseData = this.parseBody(responseText, responseType);

    if (!response.ok) {
      throw this.buildHTTPError(response.status, response.statusText, responseData);
    }

    return {
      ok: response.ok,
      status: response.status,
      data: responseData,
      text: responseText,
    };
  }
}

/**
 * Build the per-instance CA-aware HTTPS agent (SEC-006 / ADR-034).
 *
 * Returns:
 *  - `null` when the config has no `ca_cert_path` or has `verify_ssl: false`
 *    — the existing two-state behavior is preserved.
 *  - An `https.Agent({ ca, rejectUnauthorized: true })` when both
 *    `ca_cert_path` is set and verification is enabled.
 *
 * The CA bundle is read at construction time and cached on the agent —
 * subsequent requests do not re-read the file. If `ca_cert_path` is set
 * but the file cannot be read, this throws synchronously so the failure
 * surfaces at HTTPClient construction (fail-closed) rather than at the
 * first request, and never silently degrades to "verify against system
 * trust" or "skip verification".
 */
function buildCaAgent(config: NonNullable<LabConfig['api']>): https.Agent | null {
  const caPath = config.ca_cert_path;
  if (!caPath) return null;
  if (config.verify_ssl === false) return null;
  let ca: Buffer;
  try {
    ca = readFileSync(caPath);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`ca_cert_path "${caPath}" not readable: ${reason}`);
  }
  return new https.Agent({ ca, rejectUnauthorized: true });
}
