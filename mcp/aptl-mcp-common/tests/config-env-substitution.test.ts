import { describe, it, expect } from 'vitest';
import { substituteEnvVars, parseDotEnv } from '../src/config.js';

describe('substituteEnvVars', () => {
  it('substitutes a single variable', () => {
    const { result, missing } = substituteEnvVars(
      '{"password": "${MY_PASS}"}',
      { MY_PASS: 'secret' }
    );
    expect(result).toBe('{"password": "secret"}');
    expect(missing).toEqual([]);
  });

  it('substitutes multiple variables', () => {
    const { result, missing } = substituteEnvVars(
      '{"user": "${USER}", "pass": "${PASS}"}',
      { USER: 'admin', PASS: 'hunter2' }
    );
    expect(result).toBe('{"user": "admin", "pass": "hunter2"}');
    expect(missing).toEqual([]);
  });

  it('reports missing variables and leaves them as-is', () => {
    const { result, missing } = substituteEnvVars(
      '{"user": "${USER}", "pass": "${PASS}"}',
      { USER: 'admin' }
    );
    expect(result).toBe('{"user": "admin", "pass": "${PASS}"}');
    expect(missing).toEqual(['PASS']);
  });

  it('reports all missing when none are in env', () => {
    const { result, missing } = substituteEnvVars(
      '{"a": "${X}", "b": "${Y}"}',
      {}
    );
    expect(result).toBe('{"a": "${X}", "b": "${Y}"}');
    expect(missing).toEqual(['X', 'Y']);
  });

  it('returns input unchanged when no patterns present', () => {
    const input = '{"key": "plain value"}';
    const { result, missing } = substituteEnvVars(input, {});
    expect(result).toBe(input);
    expect(missing).toEqual([]);
  });

  // JSON safety — this is the critical case for passwords with special chars
  it('escapes double quotes in values so JSON stays valid', () => {
    const { result } = substituteEnvVars(
      '{"pass": "${P}"}',
      { P: 'has"quote' }
    );
    expect(result).toBe('{"pass": "has\\"quote"}');
    // The resulting string should be valid JSON
    const parsed = JSON.parse(result);
    expect(parsed.pass).toBe('has"quote');
  });

  it('escapes backslashes in values', () => {
    const { result } = substituteEnvVars(
      '{"path": "${P}"}',
      { P: 'C:\\Users\\admin' }
    );
    const parsed = JSON.parse(result);
    expect(parsed.path).toBe('C:\\Users\\admin');
  });

  it('escapes newlines and tabs in values', () => {
    const { result } = substituteEnvVars(
      '{"val": "${V}"}',
      { V: 'line1\nline2\ttab' }
    );
    const parsed = JSON.parse(result);
    expect(parsed.val).toBe('line1\nline2\ttab');
  });

  it('escapes carriage returns', () => {
    const { result } = substituteEnvVars(
      '{"val": "${V}"}',
      { V: 'before\rafter' }
    );
    const parsed = JSON.parse(result);
    expect(parsed.val).toBe('before\rafter');
  });

  it('handles combined special characters in a password', () => {
    // Realistic password with several JSON-breaking chars
    const password = 'p@ss\\"w0rd\nnewline';
    const { result } = substituteEnvVars(
      '{"password": "${PASS}"}',
      { PASS: password }
    );
    const parsed = JSON.parse(result);
    expect(parsed.password).toBe(password);
  });

  it('handles empty string value (var set but empty)', () => {
    const { result, missing } = substituteEnvVars(
      '{"val": "${V}"}',
      { V: '' }
    );
    expect(result).toBe('{"val": ""}');
    expect(missing).toEqual([]);
  });

  it('only matches ${WORD} patterns, not $VAR or other forms', () => {
    const { result, missing } = substituteEnvVars(
      '{"a": "$VAR", "b": "${VAR}", "c": "$(VAR)"}',
      { VAR: 'replaced' }
    );
    expect(result).toBe('{"a": "$VAR", "b": "replaced", "c": "$(VAR)"}');
    expect(missing).toEqual([]);
  });

  it('defaults to process.env when no env param given', () => {
    const key = '__APTL_TEST_SUBST_' + Date.now();
    process.env[key] = 'from_process';
    try {
      const { result } = substituteEnvVars(`{"v": "\${${key}}"}`);
      expect(result).toBe('{"v": "from_process"}');
    } finally {
      delete process.env[key];
    }
  });
});

describe('parseDotEnv', () => {
  it('parses simple KEY=VALUE lines', () => {
    const result = parseDotEnv('FOO=bar\nBAZ=qux');
    expect(result).toEqual({ FOO: 'bar', BAZ: 'qux' });
  });

  it('ignores comments and blank lines', () => {
    const result = parseDotEnv('# comment\n\nFOO=bar\n  # indented comment\n');
    expect(result).toEqual({ FOO: 'bar' });
  });

  it('strips double quotes from values', () => {
    const result = parseDotEnv('PASS="my secret"');
    expect(result).toEqual({ PASS: 'my secret' });
  });

  it('strips single quotes from values', () => {
    const result = parseDotEnv("PASS='my secret'");
    expect(result).toEqual({ PASS: 'my secret' });
  });

  it('handles values with = signs in them', () => {
    const result = parseDotEnv('URL=https://host:9200?foo=bar');
    expect(result).toEqual({ URL: 'https://host:9200?foo=bar' });
  });

  it('handles empty values', () => {
    const result = parseDotEnv('EMPTY=\nALSO=""');
    expect(result).toEqual({ EMPTY: '', ALSO: '' });
  });

  it('ignores lines without =', () => {
    const result = parseDotEnv('GOOD=val\nBADLINE\nALSO_GOOD=ok');
    expect(result).toEqual({ GOOD: 'val', ALSO_GOOD: 'ok' });
  });

  it('trims whitespace around keys and values', () => {
    const result = parseDotEnv('  KEY  =  value  ');
    expect(result).toEqual({ KEY: 'value' });
  });

  it('parses a realistic .env file', () => {
    const content = [
      '# APTL Lab Credentials',
      'INDEXER_USERNAME=admin',
      'INDEXER_PASSWORD=SecretPassword',
      '',
      '# Wazuh API',
      'API_USERNAME=wazuh-wui',
      'API_PASSWORD="WazuhPass123!"',
    ].join('\n');
    const result = parseDotEnv(content);
    expect(result).toEqual({
      INDEXER_USERNAME: 'admin',
      INDEXER_PASSWORD: 'SecretPassword',
      API_USERNAME: 'wazuh-wui',
      API_PASSWORD: 'WazuhPass123!',
    });
  });
});
