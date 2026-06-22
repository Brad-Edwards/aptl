import { describe, it, expect } from 'vitest';
import {
  assertPathOnlyEndpoint,
  isAbsoluteOrProtocolRelative,
  resolveApiRequestUrl,
} from '../src/endpoint-url.js';

describe('isAbsoluteOrProtocolRelative', () => {
  it('detects http(s) and protocol-relative URLs', () => {
    expect(isAbsoluteOrProtocolRelative('https://evil.example/collect')).toBe(true);
    expect(isAbsoluteOrProtocolRelative('http://evil.example/collect')).toBe(true);
    expect(isAbsoluteOrProtocolRelative('//evil.example/collect')).toBe(true);
    expect(isAbsoluteOrProtocolRelative('/api/alerts')).toBe(false);
  });
});

describe('assertPathOnlyEndpoint', () => {
  it('accepts path-only endpoints', () => {
    expect(() => assertPathOnlyEndpoint('/api/alerts')).not.toThrow();
  });

  it('rejects absolute URLs', () => {
    expect(() => assertPathOnlyEndpoint('https://attacker.example/collect')).toThrow(
      'endpoint must be a path starting with /, not an absolute URL',
    );
  });

  it('rejects protocol-relative URLs', () => {
    expect(() => assertPathOnlyEndpoint('//attacker.example/collect')).toThrow(
      'endpoint must be a path starting with /, not an absolute URL',
    );
  });

  it('rejects relative paths without a leading slash', () => {
    expect(() => assertPathOnlyEndpoint('api/alerts')).toThrow(
      'endpoint must be a path starting with /',
    );
  });
});

describe('resolveApiRequestUrl', () => {
  const baseUrl = 'https://api.example.com';

  it('resolves path endpoints against baseUrl', () => {
    expect(resolveApiRequestUrl('/test', baseUrl)).toBe('https://api.example.com/test');
  });

  it('rejects cross-origin absolute URLs when baseUrl is configured', () => {
    expect(() => resolveApiRequestUrl('https://attacker.example/collect', baseUrl)).toThrow(
      'does not match configured API origin',
    );
  });

  it('allows same-origin absolute URLs for config-owned callers', () => {
    expect(resolveApiRequestUrl('https://api.example.com/v2/alerts', baseUrl)).toBe(
      'https://api.example.com/v2/alerts',
    );
  });

  it('allows absolute URLs when baseUrl is empty (predefined query clients)', () => {
    expect(resolveApiRequestUrl('https://localhost:9200/_search', '')).toBe(
      'https://localhost:9200/_search',
    );
  });

  it('rejects protocol-relative URLs against a configured baseUrl', () => {
    expect(() => resolveApiRequestUrl('//attacker.example/collect', baseUrl)).toThrow(
      'does not match configured API origin',
    );
  });
});
