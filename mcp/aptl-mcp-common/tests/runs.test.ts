/**
 * Tests for the per-run directory contract shared with the Python
 * `src/aptl/core/runstore.py` (OBS-003).
 *
 * Mirrors the Python `TestSessionScopedHelpers` and
 * `TestResolveActiveRunDir` suites so behaviour matches across languages.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  readFileSync,
  existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  loadActiveTraceId,
  resolveActiveRunDir,
  mcpSideDir,
  kaliSideSessionDir,
  mcpSessionJsonl,
  createPtyTeeWriter,
} from '../src/runs.js';

describe('session-scoped path helpers', () => {
  const RUN_ID = 'a'.repeat(32);

  it('mcpSideDir composes under base/run', () => {
    expect(mcpSideDir('/state', RUN_ID)).toBe(`/state/runs/${RUN_ID}/mcp-side`);
  });

  it('kaliSideSessionDir composes under base/run/kali-side/session', () => {
    expect(kaliSideSessionDir('/state', RUN_ID, 'sess-1')).toBe(
      `/state/runs/${RUN_ID}/kali-side/sess-1`
    );
  });

  it('mcpSessionJsonl yields the JSONL path', () => {
    expect(mcpSessionJsonl('/state', RUN_ID, 'sess-1')).toBe(
      `/state/runs/${RUN_ID}/mcp-side/sessions/sess-1.jsonl`
    );
  });

  it.each(['../escape', 'has/slash', 'sess..', '..'])(
    'rejects unsafe session id %s',
    (bad) => {
      expect(() => kaliSideSessionDir('/state', RUN_ID, bad)).toThrow();
      expect(() => mcpSessionJsonl('/state', RUN_ID, bad)).toThrow();
    }
  );

  it.each(['../escape', 'has/slash', '..'])('rejects unsafe run id %s', (bad) => {
    expect(() => mcpSideDir('/state', bad)).toThrow();
    expect(() => kaliSideSessionDir('/state', bad, 'sess-1')).toThrow();
  });
});

describe('loadActiveTraceId / resolveActiveRunDir', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aptl-runs-test-'));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('returns undefined when trace-context.json is absent', () => {
    expect(loadActiveTraceId({ APTL_STATE_DIR: tmp })).toBeUndefined();
    expect(resolveActiveRunDir({ APTL_STATE_DIR: tmp })).toBeUndefined();
  });

  it('returns the trace_id when present', () => {
    const tid = 'b'.repeat(32);
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ trace_id: tid, span_id: 'c'.repeat(16), trace_flags: '01' })
    );
    expect(loadActiveTraceId({ APTL_STATE_DIR: tmp })).toBe(tid);
    expect(resolveActiveRunDir({ APTL_STATE_DIR: tmp })).toBe(join(tmp, 'runs', tid));
  });

  it('returns undefined when the file is malformed', () => {
    writeFileSync(join(tmp, 'trace-context.json'), 'not json');
    expect(loadActiveTraceId({ APTL_STATE_DIR: tmp })).toBeUndefined();
    expect(resolveActiveRunDir({ APTL_STATE_DIR: tmp })).toBeUndefined();
  });

  it('returns undefined when trace_id is missing', () => {
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ span_id: 'c'.repeat(16) })
    );
    expect(loadActiveTraceId({ APTL_STATE_DIR: tmp })).toBeUndefined();
    expect(resolveActiveRunDir({ APTL_STATE_DIR: tmp })).toBeUndefined();
  });

  it('rejects path-traversal in trace_id', () => {
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ trace_id: '../escape', span_id: 'c'.repeat(16) })
    );
    expect(loadActiveTraceId({ APTL_STATE_DIR: tmp })).toBeUndefined();
    expect(resolveActiveRunDir({ APTL_STATE_DIR: tmp })).toBeUndefined();
  });

  it('defaults APTL_STATE_DIR to .aptl when env unset', () => {
    // No file at default location either — should resolve to undefined,
    // not throw.
    expect(loadActiveTraceId({})).toBeUndefined();
  });
});

describe('createPtyTeeWriter', () => {
  let tmp = '';
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aptl-pty-tee-'));
    env = { APTL_STATE_DIR: tmp };
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  // No fixed-delay helper — each test awaits the writer's own
  // `flush()` (test-quality review cycle 1 finding-6). A
  // `setTimeout` race produces both flaky failures and false
  // passes under CI load.

  it('appends one JSONL line per chunk to mcp-side/sessions/<session>.jsonl', async () => {
    const tid = 'a'.repeat(32);
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ trace_id: tid, span_id: 'b'.repeat(16) }),
    );
    const writer = createPtyTeeWriter('sess-1', env);
    writer('out', Buffer.from('hello world'));
    writer('err', Buffer.from('oops'));
    await writer.flush();

    const file = join(tmp, 'runs', tid, 'mcp-side', 'sessions', 'sess-1.jsonl');
    expect(existsSync(file)).toBe(true);
    const lines = readFileSync(file, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(2);
    const r0 = JSON.parse(lines[0]);
    expect(r0.dir).toBe('out');
    expect(Buffer.from(r0.b64, 'base64').toString()).toBe('hello world');
    expect(typeof r0.ts).toBe('number');
    const r1 = JSON.parse(lines[1]);
    expect(r1.dir).toBe('err');
    expect(Buffer.from(r1.b64, 'base64').toString()).toBe('oops');
  });

  it('preserves non-UTF-8 binary bytes via base64', async () => {
    const tid = 'a'.repeat(32);
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ trace_id: tid, span_id: 'b'.repeat(16) }),
    );
    const binary = Buffer.from([0x1b, 0x5b, 0x33, 0x31, 0x6d, 0xff, 0xfe, 0xfd]);
    const writer = createPtyTeeWriter('sess-1', env);
    writer('out', binary);
    await writer.flush();

    const file = join(tmp, 'runs', tid, 'mcp-side', 'sessions', 'sess-1.jsonl');
    const rec = JSON.parse(readFileSync(file, 'utf-8').trim());
    const round = Buffer.from(rec.b64, 'base64');
    expect(round.equals(binary)).toBe(true);
  });

  it('falls back to _unbound directory when no scenario is active', async () => {
    const writer = createPtyTeeWriter('sess-1', env);
    writer('out', Buffer.from('x'));
    await writer.flush();

    const file = join(tmp, 'runs', '_unbound', 'mcp-side', 'sessions', 'sess-1.jsonl');
    expect(existsSync(file)).toBe(true);
  });

  it('best-effort: does not throw if the target dir is invalid (/dev/null/...)', async () => {
    // Construct directly with APTL_STATE_DIR pointing inside /dev/null
    // — mkdir will fail with ENOTDIR. The writer must swallow.
    const writer = createPtyTeeWriter('sess-1', { APTL_STATE_DIR: '/dev/null/x' });
    expect(() => writer('out', Buffer.from('x'))).not.toThrow();
    await writer.flush();
  });

  it('uses _invalid session subdir when session id fails validation', async () => {
    const tid = 'a'.repeat(32);
    writeFileSync(
      join(tmp, 'trace-context.json'),
      JSON.stringify({ trace_id: tid, span_id: 'b'.repeat(16) }),
    );
    const writer = createPtyTeeWriter('../escape', env);
    writer('out', Buffer.from('x'));
    await writer.flush();

    const file = join(tmp, 'runs', tid, 'mcp-side', 'sessions', '_invalid.jsonl');
    expect(existsSync(file)).toBe(true);
  });
});
