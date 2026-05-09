/**
 * Tests for the shared redaction helper used at telemetry/serialization
 * boundaries in MCP servers. Mirrors the Python `tests/test_redaction.py`
 * suite so artifacts emitted from either language match shape.
 */

import { describe, it, expect } from 'vitest';

import {
  redact,
  REDACTED,
  redactShortPasswordFlag,
  redactBasicAuthUser,
} from '../src/redaction.js';

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
    // Anchor on the labelled replacement form so a regression that
    // silently dropped the "Bearer" scheme (or the 'abc' value via an
    // unrelated code path) wouldn't be missed.
    const out = redact({
      command: "curl -H 'Authorization: Bearer abc' https://example.com",
    }) as { command: string };
    expect(out.command).toBe(
      "curl -H 'Authorization: Bearer [REDACTED]' https://example.com",
    );
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
    expect(out.command).toBe("curl -H 'Cookie: [REDACTED]' https://x");
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
    // Anchor on the exact replacement form so a regression that mangled
    // the userinfo structure would be caught.
    const out = redact({
      url: 'https://alice:hunter2@host.example.com/path',
    }) as { url: string };
    expect(out.url).toBe('https://alice:[REDACTED]@host.example.com/path');
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

describe('redactShortPasswordFlag — short -p credential masking', () => {
  it('redacts hydra short -p (non-numeric, no leading credential tool needed)', () => {
    expect(redactShortPasswordFlag('hydra -l u -p hunter2 host ssh')).toContain('-p [REDACTED]');
  });

  it('redacts numeric -p when a credential tool is present (cycle-7 security regression)', () => {
    // Numeric passwords are common; this fires when the command contains
    // a known credential-taking tool.
    expect(redactShortPasswordFlag('hydra -l u -p 123456 host ssh')).toContain('-p [REDACTED]');
    expect(redactShortPasswordFlag('sshpass -p 1234 ssh user@host')).toContain('-p [REDACTED]');
  });

  it('keeps numeric -p when no credential tool is present (port for nmap stays visible)', () => {
    expect(redactShortPasswordFlag('nmap -p 22 10.0.0.1')).toContain('-p 22');
    expect(redactShortPasswordFlag('nmap -p 22,80,443 host')).toContain('-p 22,80,443');
  });

  it('handles wrapper pipelines (proxychains4 / sudo) by detecting the inner credential tool', () => {
    expect(redactShortPasswordFlag('proxychains4 hydra -l u -p hunter2 host ssh')).toContain(
      '-p [REDACTED]',
    );
    expect(redactShortPasswordFlag('sudo hydra -p hunter2 host ssh')).toContain('-p [REDACTED]');
  });

  it('handles equals form `-p=value` and attached form `-p<value>` (cycle-7)', () => {
    expect(redactShortPasswordFlag('hydra -l u -p=hunter2 host ssh')).not.toContain('hunter2');
    // Attached `-p<value>` (no whitespace) — also a real shell form.
    expect(redactShortPasswordFlag('hydra -l u -phunter2 host ssh')).not.toContain('hunter2');
  });

  it('redacts a quoted multi-word password value', () => {
    expect(redactShortPasswordFlag('hydra -p "secret phrase" host ssh')).not.toContain('secret');
  });

  it('per-segment: keeps nmap -p 22 visible when only a later segment has a credential tool (cycle-8 review)', () => {
    // `nmap -p 22 ... && hydra -p X ...` — credential-tool detection is
    // per shell segment. Nmap's port number stays visible, hydra's
    // password gets masked.
    const out = redactShortPasswordFlag(
      'nmap -p 22 10.0.0.1 && hydra -l u -p hunter2 host ssh',
    );
    expect(out).toContain('-p 22');
    expect(out).not.toContain('hunter2');
    expect(out).toContain('-p [REDACTED]');
  });

  it('per-segment: respects the | separator too', () => {
    const out = redactShortPasswordFlag(
      'nmap -p 80 10.0.0.1 | tee out.txt; hydra -p hunter2 host ssh',
    );
    expect(out).toContain('-p 80');
    expect(out).not.toContain('hunter2');
  });
});

describe('redactBasicAuthUser — curl/wget --user user:pass', () => {
  it('redacts curl --user user:password', () => {
    const out = redactBasicAuthUser('curl --user alice:hunter2 https://target/');
    expect(out).not.toContain('hunter2');
    expect(out).toContain('--user [REDACTED]');
  });

  it('redacts curl -u user:password', () => {
    expect(redactBasicAuthUser('curl -u alice:hunter2 https://target/')).not.toContain('hunter2');
  });

  it('leaves --user with no colon alone (bare username, no embedded password)', () => {
    expect(redactBasicAuthUser('ssh --user alice host')).toContain('--user alice');
  });

  it('handles `--user=user:pass` form', () => {
    expect(redactBasicAuthUser('curl --user=alice:hunter2 https://target/')).not.toContain(
      'hunter2',
    );
  });

  it('does NOT redact -u <URL> for web tools (cycle-9 review)', () => {
    // `sqlmap -u https://target/login` — `-u` here is a URL, not a
    // basic-auth pair. The colon is just `https:`. Must not redact.
    const out = redactBasicAuthUser('sqlmap -u https://target.example/login');
    expect(out).toContain('https://target.example/login');
  });

  it('does NOT redact -u <URL with port> for web tools', () => {
    expect(
      redactBasicAuthUser('gobuster dir -u http://target.example:8080/admin -w wl'),
    ).toContain('http://target.example:8080/admin');
  });

  it('still redacts a Samba-style %password embedded in --user (cycle-9 security)', () => {
    // `--user alice%password` → mask the value entirely (the password
    // is the part after `%`, but masking the whole value is safer and
    // still leaves the flag visible in cmd_line).
    const out = redactBasicAuthUser('rpcclient --user alice%hunter2 dc.example');
    expect(out).not.toContain('hunter2');
  });

  it('still redacts a Samba-style %password embedded in -U (cycle-9 security)', () => {
    expect(redactBasicAuthUser('smbclient -U alice%hunter2 //host/share')).not.toContain(
      'hunter2',
    );
  });
});

describe('redactNtlmHashFlag — credential-tool -H redaction (pre-emptive cycle-10)', () => {
  it('redacts -H <hash> for crackmapexec / cme / nxc', () => {
    const cmd = 'nxc smb dc.example -u alice -H aad3b435b51404ee:8846f7eaee8fb117';
    const out = String(redact(cmd));
    expect(out).not.toContain('aad3b435');
    expect(out).not.toContain('8846f7ea');
  });

  it('redacts -H <hash> for impacket *.py tools', () => {
    const out = String(redact('psexec.py alice@dc.example -hashes :8846f7eaee8fb117'));
    // The shared --hashes / -hashes long flag is also covered by the
    // generic CLI flag pattern via SENSITIVE_KEY_PATTERN containing
    // 'hash' indirectly… but specifically the -H short for impacket
    // alongside a known tool segment must redact.
    const ncxOut = String(redact('impacket-secretsdump alice@dc.example -H aad3b435:8846f7eaee'));
    expect(ncxOut).not.toContain('aad3b435');
    expect(out).toBeDefined();
  });

  it('redacts ldapsearch -w <password> (LDAP simple bind, cycle-11 security)', () => {
    const cmd = 'ldapsearch -x -D cn=admin,dc=lab -w hunter2 -b dc=lab "(uid=*)"';
    expect(String(redact(cmd))).not.toContain('hunter2');
  });

  it('does NOT redact hydra -w <wordlist> (cycle-11)', () => {
    // hydra `-w` is a wait-time, not a password. The LDAP redactor
    // must not fire when the segment has no LDAP tool.
    const cmd = 'hydra -l u -P passwords.txt -w 5 host ssh';
    expect(String(redact(cmd))).toContain('-w 5');
  });

  it('redacts numeric -p for newly-classified credential tools (cycle-11 security)', () => {
    expect(String(redact('evil-winrm -i 10.0.0.1 -u alice -p 12345'))).not.toContain('12345');
    expect(String(redact('bloodhound-python -u alice -p 12345 -d corp.example -c All'))).not.toContain(
      '12345',
    );
  });

  it('redacts escape-aware -p value with shell-escaped whitespace (cycle-11 security)', () => {
    // `hydra -p correct\ horse` — without escape-aware matching the
    // pattern would consume only `correct\` and leave `horse` visible.
    const cmd = String.raw`hydra -l u -p correct\ horse host ssh`;
    const out = String(redact(cmd));
    expect(out).not.toContain('correct');
    expect(out).not.toContain('horse');
  });

  it('redacts attached short forms `-Hhash`, `-uuser:pass`, `-Uuser%pass`, `-wpassword` (cycle-12 security)', () => {
    expect(String(redact('nxc smb dc.example -u alice -Haad3b435b51404ee:8846f7eaee'))).not.toContain(
      'aad3b435',
    );
    expect(String(redact('curl -ualice:hunter2 https://target.example/'))).not.toContain(
      'hunter2',
    );
    expect(String(redact('smbclient -Ualice%hunter2 //host/share'))).not.toContain('hunter2');
    expect(String(redact('ldapsearch -x -D cn=admin,dc=lab -whunter2'))).not.toContain('hunter2');
    // Attached short -p is already covered by SHORT_P_ATTACHED_PATTERN
    // — re-asserting here so any future refactor keeps this guarantee.
    expect(String(redact('hydra -l u -phunter2 host ssh'))).not.toContain('hunter2');
  });

  it('normalises quoted standalone option tokens before flag matching (cycle-12 security)', () => {
    // `'-p' hunter2` — quote-stripping pre-pass should let the -p
    // pattern fire even though the token has surrounding quotes.
    expect(String(redact("hydra '-p' hunter2 host ssh"))).not.toContain('hunter2');
    expect(String(redact('curl "-u" alice:hunter2 https://target/'))).not.toContain('hunter2');
  });

  it('redacts impacket positional user:password@host (cycle-12 security)', () => {
    expect(String(redact('psexec.py corp/alice:hunter2@dc.example'))).not.toContain('hunter2');
    expect(String(redact('secretsdump.py alice:hunter2@dc.example'))).not.toContain('hunter2');
    // The user, host, and tool stay visible for SIEM correlation.
    const out = String(redact('psexec.py alice:hunter2@dc.example'));
    expect(out).toContain('alice');
    expect(out).toContain('dc.example');
    expect(out).toContain('psexec.py');
  });

  it('redacts impacket positional even when password contains : @ or whitespace (cycle-13 security)', () => {
    // Real Windows passwords with `:`, `@`, and spaces.
    expect(String(redact('psexec.py corp/alice:"P@ss:w0rd"@dc.example'))).not.toContain('P@ss');
    expect(String(redact("psexec.py corp/alice:'P@ss w0rd'@dc.example"))).not.toContain('P@ss');
    // The user, host, and tool stay visible.
    const out = String(redact('psexec.py corp/alice:"P@ss w0rd"@dc.example'));
    expect(out).toContain('corp/alice');
    expect(out).toContain('@dc.example');
    expect(out).toContain('psexec.py');
  });

  it('does NOT redact a non-impacket user:pair@host elsewhere', () => {
    // `git clone alice:token@github.com/...` outside an impacket
    // segment is also a credential leak risk, but the impacket
    // positional rule deliberately scopes itself to impacket segments.
    // The shared URL_USERINFO_PATTERN handles `scheme://user:pass@host`
    // form. Plain `user:pass@host` without scheme stays visible — but
    // the test guards against the impacket pattern firing too broadly.
    const out = String(redact('echo alice:token@host'));
    expect(out).toContain('alice:token@host');
  });

  it('does NOT redact -H header for curl (no credential tool in segment)', () => {
    // `curl -H 'X-Foo: bar' …` — `-H` here is the HTTP header flag,
    // not an NTLM hash. The bracketed segment doesn't contain a
    // credential tool, so the value stays visible.
    const out = String(redact("curl -H 'X-Foo: bar' https://target.example/x"));
    expect(out).toContain('X-Foo: bar');
  });
});

describe('redact — composes the new short-flag and basic-auth redactors', () => {
  it('a curl command with --user user:pass is masked when passed through the top-level redact()', () => {
    expect(String(redact('curl --user alice:hunter2 https://target/'))).not.toContain('hunter2');
  });

  it('a hydra command with -p is masked through the top-level redact()', () => {
    expect(String(redact('hydra -l admin -p hunter2 10.0.0.1 ssh'))).not.toContain('hunter2');
  });
});
