/**
 * Tests for the shared redaction helper used at telemetry/serialization
 * boundaries in MCP servers. Mirrors the Python `tests/test_redaction.py`
 * suite so artifacts emitted from either language match shape.
 */

import { describe, it, expect } from 'vitest';

import { redact, REDACTED } from '../src/redaction.js';

describe('redact - sensitive scalars', () => {
  it('replaces password value', () => {
    expect(redact({ password: 'hunter2' })).toEqual({ password: REDACTED });
  });

  it.each([
    'password',
    'passwd',
    'passphrase',
    'pass',
    'db_pass',
    'secret',
    'token',
    'credential',
    'credentials',
    'authorization',
    'cookie',
    'jwt',
    'bearer',
    'api_key',
    'apikey',
    'key',
    'session',
    'session_id',
  ])('redacts each sensitive token: %s', (key) => {
    expect(redact({ [key]: 'x' })).toEqual({ [key]: REDACTED });
  });

  it.each(['Password', 'API_KEY', 'Authorization', 'JWT', 'Cookie', 'SECRET'])(
    'is case-insensitive: %s',
    (key) => {
      expect(redact({ [key]: 'x' })).toEqual({ [key]: REDACTED });
    },
  );

  it('redacts credential-value class (synthetic placeholders)', () => {
    // Real lab defaults are not embedded in this test; synthetic
    // placeholders prove the redactor masks credential-shaped values.
    const out = redact({
      credentials: 'PLACEHOLDER_USER/PLACEHOLDER_PASSWORD',
      password: 'PLACEHOLDER_PASSWORD_VALUE',
      token: 'PLACEHOLDER_JWT_VALUE',
    }) as Record<string, unknown>;
    for (const v of Object.values(out)) {
      expect(v).toBe(REDACTED);
    }
  });

  it('redacts non-string sensitive values', () => {
    expect(redact({ password: 12345, token: null, secret: true })).toEqual({
      password: REDACTED,
      token: REDACTED,
      secret: REDACTED,
    });
  });

  it('preserves non-sensitive scalars', () => {
    expect(redact({ name: 'wazuh-manager', port: 55000, ok: true })).toEqual({
      name: 'wazuh-manager',
      port: 55000,
      ok: true,
    });
  });
});

describe('redact - safe-key allowlist', () => {
  it.each([
    'key_path',
    'key_file',
    'keypath',
    'keyfile',
    'ssh_key_path',
    'ssh_keyfile',
    'public_key',
    'publickey',
  ])('does not redact path-like key name: %s', (key) => {
    const out = redact({ [key]: '~/.ssh/aptl_lab_key' });
    expect(out).toEqual({ [key]: '~/.ssh/aptl_lab_key' });
  });

  it.each(['ssh_key', 'sshkey'])(
    'treats bare %s as sensitive (could be private key material)',
    (key) => {
      const out = redact({ [key]: 'anything' });
      expect(out).toEqual({ [key]: REDACTED });
    },
  );
});

describe('redact - recursion', () => {
  it('recurses into nested objects', () => {
    expect(redact({ outer: { password: 'p', host: 'h' } })).toEqual({
      outer: { password: REDACTED, host: 'h' },
    });
  });

  it('recurses into arrays of objects', () => {
    expect(redact({ services: [{ credentials: 'c', name: 'n' }] })).toEqual({
      services: [{ credentials: REDACTED, name: 'n' }],
    });
  });

  it('recurses into top-level arrays', () => {
    expect(redact([{ password: 'p' }, 'scalar'])).toEqual([
      { password: REDACTED },
      'scalar',
    ]);
  });

  it('handles deeply nested structures', () => {
    expect(redact({ a: { b: { c: [{ secret: 's', ok: 1 }] } } })).toEqual({
      a: { b: { c: [{ secret: REDACTED, ok: 1 }] } },
    });
  });
});

describe('redact - immutability', () => {
  it('does not mutate input objects', () => {
    const inp = { password: 'p', nested: { token: 't' } };
    const snapshot = JSON.parse(JSON.stringify(inp));
    redact(inp);
    expect(inp).toEqual(snapshot);
  });

  it('does not mutate input arrays', () => {
    const inp = [{ password: 'p' }];
    const snapshot = JSON.parse(JSON.stringify(inp));
    redact(inp);
    expect(inp).toEqual(snapshot);
  });
});

describe('redact - edge cases', () => {
  it('returns empty object unchanged', () => {
    expect(redact({})).toEqual({});
  });

  it('returns empty array unchanged', () => {
    expect(redact([])).toEqual([]);
  });

  it('returns top-level scalars unchanged', () => {
    expect(redact('hello')).toBe('hello');
    expect(redact(42)).toBe(42);
    expect(redact(null)).toBeNull();
    expect(redact(undefined)).toBeUndefined();
  });

  it('redacts compound key names containing sensitive tokens', () => {
    expect(
      redact({
        ssl_authorization_header: 'Bearer xyz',
        oauth_token_url: 'https://example.com/token',
        user_password_hash: 'bcrypt$...',
      }),
    ).toEqual({
      ssl_authorization_header: REDACTED,
      oauth_token_url: REDACTED,
      user_password_hash: REDACTED,
    });
  });
});

describe('redact - string content traversal', () => {
  it('parses JSON-string values and redacts inner secrets', () => {
    const out = redact({ body: '{"password":"hunter2","host":"h"}' }) as Record<string, string>;
    expect(out.body).not.toContain('hunter2');
    expect(out.body).toContain('[REDACTED]');
    expect(out.body).toContain('"host":"h"');
  });

  it('parses JSON-array string values', () => {
    const out = redact({ envelope: '[{"token":"abc"}]' }) as Record<string, string>;
    expect(out.envelope).not.toContain('abc');
    expect(out.envelope).toContain('[REDACTED]');
  });

  it('handles MCP content[].text envelope', () => {
    // Real MCP response shape: tool returns { content: [{type, text}] } where
    // `text` is `JSON.stringify(actual_data)`. The redactor must reach
    // through the string envelope.
    const out = redact({
      content: [
        { type: 'text', text: '{"data":{"api_key":"abc","ok":true}}' },
      ],
    }) as { content: Array<{ type: string; text: string }> };
    expect(out.content[0].text).not.toContain('abc');
    expect(out.content[0].text).toContain('[REDACTED]');
    expect(out.content[0].text).toContain('"ok":true');
  });

  it('leaves non-JSON strings without inline secrets unchanged', () => {
    expect(redact({ msg: 'hello world' })).toEqual({ msg: 'hello world' });
    expect(redact({ msg: 'not really {json' })).toEqual({ msg: 'not really {json' });
  });

  it.each([
    ['Authorization: Bearer abc.def.ghi', 'Authorization: Bearer [REDACTED]'],
    ['authorization: Basic dXNlcjpwYXNz', 'authorization: Basic [REDACTED]'],
    ['Bearer raw-token-value', 'Bearer [REDACTED]'],
    ['--password=hunter2', '--password=[REDACTED]'],
    ['password: hunter2', 'password: [REDACTED]'],
    ['api_key=abc123', 'api_key=[REDACTED]'],
    ['token=ey.signed.jwt', 'token=[REDACTED]'],
    ['--password hunter2', '--password [REDACTED]'],
    ['--token abc123', '--token [REDACTED]'],
  ])('redacts inline %s -> %s', (input, expected) => {
    const out = redact({ command: input }) as { command: string };
    expect(out.command).toBe(expected);
  });

  it('redacts curl command with Authorization header', () => {
    const out = redact({
      command: "curl -H 'Authorization: Bearer abc' https://example.com",
    }) as { command: string };
    expect(out.command).not.toContain('abc');
    expect(out.command).toContain('[REDACTED]');
  });

  it('redacts URL query string with sensitive params', () => {
    const out = redact({
      url: 'https://api.example.com?api_key=secret123&user=alice',
    }) as { url: string };
    expect(out.url).not.toContain('secret123');
    expect(out.url).toContain('user=alice');
  });

  it('preserves the trailing quote around Authorization header value', () => {
    const out = redact({
      command: "curl -H 'Authorization: Bearer abc.def' https://x",
    }) as { command: string };
    expect(out.command).not.toContain('abc.def');
    // Authorization scheme labelled, value masked, surrounding quotes intact.
    expect(out.command).toContain('Bearer [REDACTED]');
    expect(out.command).toContain("'Authorization: Bearer [REDACTED]'");
    expect(out.command.endsWith('https://x')).toBe(true);
  });

  it('redacts Cookie header', () => {
    const out = redact({
      command: "curl -H 'Cookie: session=xyz' https://x",
    }) as { command: string };
    expect(out.command).not.toContain('session=xyz');
    expect(out.command).toContain('[REDACTED]');
  });

  it('redacts multi-segment Cookie header', () => {
    // `;`-delimited cookie segments must all be masked, not just the
    // first one — a Cookie header is one credential blob.
    const out = redact({
      command:
        "curl -H 'Cookie: lang=en; connect.sid=SECRET_VALUE' https://x",
    }) as { command: string };
    expect(out.command).not.toContain('lang=en');
    expect(out.command).not.toContain('SECRET_VALUE');
    expect(out.command).toContain('Cookie: [REDACTED]');
  });

  it('redacts Set-Cookie response header', () => {
    const out = redact({
      text: 'Set-Cookie: sessionId=abc.def; Path=/; HttpOnly',
    }) as { text: string };
    expect(out.text).not.toContain('sessionId=abc.def');
    expect(out.text).toContain('Set-Cookie: [REDACTED]');
  });

  it.each([
    ['access_token=SECRET_AT', 'SECRET_AT'],
    ['refresh_token=SECRET_RT', 'SECRET_RT'],
    ['client_secret=SECRET_CS', 'SECRET_CS'],
    ['db_password=SECRET_DB', 'SECRET_DB'],
    ['--client-secret SECRET_CLI', 'SECRET_CLI'],
    ['--access-token SECRET_AT2', 'SECRET_AT2'],
  ])('redacts compound credential name in %s', (input, leakToken) => {
    // `_` and `-` must not block matching — `\b<key>\b` boundaries
    // would fail because `_` is a word character.
    const out = redact({ command: input }) as { command: string };
    expect(out.command).not.toContain(leakToken);
    expect(out.command).toContain(REDACTED);
  });

  it('redacts URL userinfo password', () => {
    const out = redact({
      url: 'https://alice:hunter2@host.example.com/path',
    }) as { url: string };
    expect(out.url).not.toContain('hunter2');
    expect(out.url).toContain('alice');
    expect(out.url).toContain('host.example.com/path');
    expect(out.url).toContain('[REDACTED]');
  });

  it('redacts PEM private key block', () => {
    const pem = [
      'before',
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ',
      'secretkeymaterial...',
      '-----END PRIVATE KEY-----',
      'after',
    ].join('\n');
    const out = redact({ blob: pem }) as { blob: string };
    expect(out.blob).not.toContain('MIIEvQIBADANBg');
    expect(out.blob).not.toContain('secretkeymaterial');
    expect(out.blob).toContain('-----BEGIN PRIVATE KEY-----');
    expect(out.blob).toContain('-----END PRIVATE KEY-----');
    expect(out.blob).toContain('before');
    expect(out.blob).toContain('after');
  });

  it('redacts PEM RSA private key block', () => {
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'secretmaterial',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n');
    const out = redact({ blob: pem }) as { blob: string };
    expect(out.blob).not.toContain('secretmaterial');
    expect(out.blob).toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(out.blob).toContain('-----END RSA PRIVATE KEY-----');
  });
});

describe('redact - array pair-form CLI flags', () => {
  it('redacts the value following a sensitive --flag in an array', () => {
    expect(redact(['--password', 'hunter2', '--verbose'])).toEqual([
      '--password',
      REDACTED,
      '--verbose',
    ]);
  });

  it('handles multiple pair-form flags in one array', () => {
    expect(redact(['--password', 'p1', '--token', 't2', '--ok'])).toEqual([
      '--password',
      REDACTED,
      '--token',
      REDACTED,
      '--ok',
    ]);
  });

  it('leaves non-sensitive flag values intact', () => {
    expect(redact(['--verbose', 'true', '--retries', '3'])).toEqual([
      '--verbose',
      'true',
      '--retries',
      '3',
    ]);
  });

  it('redacts only adjacent values for sensitive flags', () => {
    expect(redact(['--port', '22', '--password', 'x'])).toEqual([
      '--port',
      '22',
      '--password',
      REDACTED,
    ]);
  });
});
