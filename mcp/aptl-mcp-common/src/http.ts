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

    // Configure SSL verification
    if (!verify_ssl) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
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

      const responseText = await response.text();
      let responseData: any;

      try {
        responseData = options.responseType === 'text' ? responseText : JSON.parse(responseText);
      } catch {
        responseData = responseText;
      }

      if (!response.ok) {
        const error = new Error(`HTTP ${response.status}: ${response.statusText}`) as HTTPError;
        error.statusCode = response.status;
        error.response = responseData;
        throw error;
      }

      return {
        ok: response.ok,
        status: response.status,
        data: responseData,
        text: responseText,
      };
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`Request timeout after ${timeout}ms`);
      }
      throw error;
    } finally {
      // Reset SSL verification
      if (!verify_ssl) {
        delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      }
    }
  }
}