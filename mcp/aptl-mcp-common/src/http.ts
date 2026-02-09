import https from 'node:https';
import http from 'node:http';
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
  constructor(private config: LabConfig['api']) {
    if (!config) {
      throw new Error('API configuration is required');
    }
  }

  /**
   * Build authentication headers based on config
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
        
      default:
        return {};
    }
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

    // Build headers
    const authHeaders = this.buildAuthHeaders();
    const headers = {
      'Content-Type': 'application/json',
      ...default_headers,
      ...authHeaders,
      ...options.headers,
    };

    // Use node:https with per-request agent when SSL verification is disabled,
    // avoiding the process-global NODE_TLS_REJECT_UNAUTHORIZED race condition
    if (!verify_ssl) {
      return this.makeRequestWithAgent(url, method, headers, options, timeout);
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
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
   * Make HTTP request using node:https with a per-request insecure agent.
   * Used when verify_ssl is false to avoid mutating process.env.
   */
  private makeRequestWithAgent(
    url: string,
    method: string,
    headers: Record<string, string>,
    options: { body?: any; responseType?: 'json' | 'text' },
    timeout: number
  ): Promise<HTTPResponse> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const transport = parsed.protocol === 'https:' ? https : http;
      const bodyStr = options.body ? JSON.stringify(options.body) : undefined;

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
        ...(parsed.protocol === 'https:' ? { agent: insecureAgent } : {}),
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