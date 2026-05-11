import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

vi.mock('aptl-mcp-common', async () => {
  const actual = await vi.importActual<typeof import('../../aptl-mcp-common/src/redaction.js')>(
    '../../aptl-mcp-common/src/redaction.js',
  );
  return { redact: actual.redact };
});

import {
  appendCaptureRecord,
  buildCaptureRecord,
  captureFilePath,
  captureToolCall,
} from '../src/capture.js';

let tmpDir = '';
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'aptl-red-capture-'));
  env = { APTL_STATE_DIR: tmpDir };
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('captureFilePath', () => {
  it('writes inside APTL_STATE_DIR by default', () => {
    expect(captureFilePath({ APTL_STATE_DIR: '/tmp/example' })).toBe(
      '/tmp/example/red-tool-calls.jsonl',
    );
  });

  it('honours APTL_RED_CAPTURE_PATH override', () => {
    expect(
      captureFilePath({ APTL_RED_CAPTURE_PATH: '/var/log/red.jsonl', APTL_STATE_DIR: '/x' }),
    ).toBe('/var/log/red.jsonl');
  });

  it('falls back to .aptl when APTL_STATE_DIR is unset', () => {
    expect(captureFilePath({})).toMatch(/\.aptl\/red-tool-calls\.jsonl$/);
  });
});

describe('buildCaptureRecord — redaction', () => {
  it('redacts credential-shaped keys in args', () => {
    const r = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: { command: 'echo hi', password: 'hunter2' },
      result: { content: [{ type: 'text', text: 'hi' }] },
      durationMs: 10,
    });
    const args = r.args as Record<string, unknown>;
    expect(args.password).toBe('[REDACTED]');
    expect(args.command).toBe('echo hi');
  });

  it('redacts credential-shaped tokens inside the command string', () => {
    const r = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: { command: 'hydra -l u -p hunter2 host ssh' },
      result: { content: [{ type: 'text', text: 'ok' }] },
      durationMs: 10,
    });
    const args = r.args as Record<string, unknown>;
    expect(args.command).not.toContain('hunter2');
  });

  it('records error message (redacted) instead of result on failure', () => {
    const r = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: { command: 'echo hi' },
      error: new Error('connection refused'),
      durationMs: 10,
    });
    expect(r.error).toBe('connection refused');
    expect(r.result).toBeUndefined();
  });

  it('always emits a numeric epoch-ms time and the agent name', () => {
    const before = Date.now();
    const r = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: {},
      durationMs: 10,
    });
    const after = Date.now();
    expect(r.time).toBeGreaterThanOrEqual(before);
    expect(r.time).toBeLessThanOrEqual(after);
    expect(r.agent_name).toBe('aptl-kali-red');
  });

  it('propagates the session_id when provided', () => {
    const r = buildCaptureRecord({
      toolName: 'kali_session_command',
      agentName: 'aptl-kali-red',
      sessionId: 'sess-abc',
      args: { session_id: 'sess-abc', command: 'whoami' },
      result: {},
      durationMs: 1,
    });
    expect(r.session_id).toBe('sess-abc');
  });
});

describe('appendCaptureRecord — JSONL append', () => {
  it('appends a single JSONL line per call', async () => {
    const r1 = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: { command: 'echo a' },
      result: 'a',
      durationMs: 1,
    });
    const r2 = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: { command: 'echo b' },
      result: 'b',
      durationMs: 1,
    });
    await appendCaptureRecord(r1, env);
    await appendCaptureRecord(r2, env);
    const file = captureFilePath(env);
    expect(existsSync(file)).toBe(true);
    const content = readFileSync(file, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).args.command).toBe('echo a');
    expect(JSON.parse(lines[1]).args.command).toBe('echo b');
  });

  it('creates the parent directory on first write', async () => {
    const nested = join(tmpDir, 'nested', 'deep');
    const nestedEnv = { APTL_STATE_DIR: nested };
    const r = buildCaptureRecord({
      toolName: 'x',
      agentName: 'aptl-kali-red',
      args: {},
      result: 'ok',
      durationMs: 1,
    });
    await appendCaptureRecord(r, nestedEnv);
    expect(existsSync(captureFilePath(nestedEnv))).toBe(true);
  });

  it('best-effort: never throws on permission/io errors', async () => {
    // `/dev/null/red.jsonl` — /dev/null exists but is not a directory,
    // so the mkdir-recursive helper fails fast with ENOTDIR.
    const bogus = { APTL_RED_CAPTURE_PATH: '/dev/null/red.jsonl' };
    await expect(
      appendCaptureRecord(
        buildCaptureRecord({
          toolName: 'x',
          agentName: 'aptl-kali-red',
          args: {},
          result: 'ok',
          durationMs: 1,
        }),
        bogus,
      ),
    ).resolves.toBeUndefined();
  });
});

describe('captureToolCall — end-to-end', () => {
  it('writes a redacted record and resolves without throwing', async () => {
    await captureToolCall(
      {
        toolName: 'kali_run_command',
        agentName: 'aptl-kali-red',
        args: {
          command: 'curl --user alice:hunter2 https://target.example/',
          api_key: 'should-be-redacted',
        },
        result: { content: [{ type: 'text', text: 'ok' }] },
        durationMs: 5,
      },
      env,
    );
    const content = readFileSync(captureFilePath(env), 'utf-8');
    expect(content).not.toContain('hunter2');
    expect(content).not.toContain('should-be-redacted');
    expect(content).toContain('curl');
  });
});

describe('buildCaptureRecord — exit_code / signal / success (cycle-11 review)', () => {
  it('records exit_code, signal, and success when provided', () => {
    const r = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: { command: 'whoami' },
      exitCode: 0,
      success: true,
      durationMs: 1,
    });
    expect(r.exit_code).toBe(0);
    expect(r.success).toBe(true);
    expect(r.signal).toBeUndefined();
  });

  it('records signal name when the command was killed', () => {
    const r = buildCaptureRecord({
      toolName: 'kali_run_command',
      agentName: 'aptl-kali-red',
      args: { command: 'sleep 999' },
      exitCode: 0,
      signal: 'SIGTERM',
      success: false,
      durationMs: 1,
    });
    expect(r.signal).toBe('SIGTERM');
    expect(r.success).toBe(false);
  });
});

describe('buildCaptureRecord — opt-in result persistence (cycle-11 security)', () => {
  it('OMITS result by default — tool stdout can contain unlabelled credentials', () => {
    const r = buildCaptureRecord(
      {
        toolName: 'kali_run_command',
        agentName: 'aptl-kali-red',
        args: { command: 'mimikatz' },
        result: { content: [{ type: 'text', text: 'NTLM hash: aad3b435b51404eeaad3b4...' }] },
        durationMs: 5,
      },
      {}, // no APTL_RED_CAPTURE_INCLUDE_RESULT
    );
    expect(r.result).toBeUndefined();
  });

  it('INCLUDES result when APTL_RED_CAPTURE_INCLUDE_RESULT=true', () => {
    const r = buildCaptureRecord(
      {
        toolName: 'kali_run_command',
        agentName: 'aptl-kali-red',
        args: { command: 'whoami' },
        result: { content: [{ type: 'text', text: 'kali\n' }] },
        durationMs: 5,
      },
      { APTL_RED_CAPTURE_INCLUDE_RESULT: 'true' },
    );
    expect(r.result).toBeDefined();
  });

  it('still records error message even when result is opt-out', () => {
    const r = buildCaptureRecord(
      {
        toolName: 'kali_run_command',
        agentName: 'aptl-kali-red',
        args: { command: 'whoami' },
        error: new Error('connection refused'),
        durationMs: 5,
      },
      {},
    );
    expect(r.error).toBe('connection refused');
    expect(r.result).toBeUndefined();
  });
});
