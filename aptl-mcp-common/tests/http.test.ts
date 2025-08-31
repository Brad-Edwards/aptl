import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HTTPClient } from '../src/http.js';

// Mock fetch globally
global.fetch = vi.fn();

describe('HTTPClient', () => {
  const mockFetch = vi.mocked(global.fetch);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('creates client with valid API config', () => {
    const config = {
      baseUrl: 'https://api.example.com',
      auth: { type: 'basic' as const, username: 'user', password: 'pass' }
    };
    
    const client = new HTTPClient(config);
    expect(client).toBeDefined();
  });

  it('throws error with no API config', () => {
    expect(() => new HTTPClient(undefined)).toThrow('API configuration is required');
  });

  it('builds basic auth headers correctly', async () => {
    const config = {
      baseUrl: 'https://api.example.com',
      auth: { type: 'basic' as const, username: 'user', password: 'pass' }
    };
    
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{"result": "success"}')
    } as any);

    const client = new HTTPClient(config);
    await client.makeRequest('/test');
    
    const expectedAuth = Buffer.from('user:pass').toString('base64');
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.example.com/test',
      expect.objectContaining({
        headers: expect.objectContaining({
          'Authorization': `Basic ${expectedAuth}`
        })
      })
    );
  });

  it('builds bearer auth headers correctly', async () => {
    const config = {
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'abc123' }
    };
    
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{"result": "success"}')
    } as any);

    const client = new HTTPClient(config);
    await client.makeRequest('/test');
    
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.example.com/test',
      expect.objectContaining({
        headers: expect.objectContaining({
          'Authorization': 'Bearer abc123'
        })
      })
    );
  });

  it('handles query parameters', async () => {
    const config = {
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'abc123' }
    };
    
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve('{"result": "success"}')
    } as any);

    const client = new HTTPClient(config);
    await client.makeRequest('/search', 'GET', {
      params: { q: 'test', limit: 10 }
    });
    
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.example.com/search?q=test&limit=10',
      expect.any(Object)
    );
  });

  it('throws error on HTTP failure', async () => {
    const config = {
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'abc123' }
    };
    
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      text: () => Promise.resolve('{"error": "Not found"}')
    } as any);

    const client = new HTTPClient(config);
    
    await expect(client.makeRequest('/missing')).rejects.toThrow('HTTP 404: Not Found');
  });

  it('handles timeout', async () => {
    const config = {
      baseUrl: 'https://api.example.com',
      auth: { type: 'bearer' as const, token: 'abc123' },
      timeout: 100
    };
    
    mockFetch.mockImplementationOnce(() => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 50);
      return Promise.reject(new DOMException('AbortError', 'AbortError'));
    });

    const client = new HTTPClient(config);
    
    await expect(client.makeRequest('/slow')).rejects.toThrow('Request timeout after 100ms');
  });
});