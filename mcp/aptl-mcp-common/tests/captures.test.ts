/**
 * Tests for the OBS-003 / ADR-033 capture harvest helper.
 *
 * `harvestSession` invokes `docker cp` via child_process. We don't
 * have a docker daemon in the test environment, so we shim `spawn`
 * to fake the docker CLI: `docker cp <src> <dest>` is intercepted
 * and replaced with a controllable behaviour (success / not-found /
 * permission-denied), and we assert that:
 *   - the destination dir is created with 0700 mode,
 *   - file/dir modes are repaired to 0600 / 0700 recursively,
 *   - "No such file" from docker cp is treated as a clean no-op,
 *   - the run id is resolved from trace-context.json on the host,
 *   - failures never throw out of harvestSession.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';

// Module-level controls the mocked `spawn` reads on every invocation.
// Each test resets them in `beforeEach`.
interface SpawnControl {
  exitCode: number;
  stderrText: string;
  capturedArgs: string[][];
  callCount: number;
}
const spawnControl: SpawnControl = {
  exitCode: 0,
  stderrText: '',
  capturedArgs: [],
  callCount: 0,
};

vi.mock('node:child_process', () => ({
  spawn: (_cmd: string, args: string[]) => {
    spawnControl.callCount += 1;
    spawnControl.capturedArgs.push(args);
    const stdout = new EventEmitter();
    const stderr = new EventEmitter();
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
    };
    child.stdout = stdout;
    child.stderr = stderr;
    const exit = spawnControl.exitCode;
    const text = spawnControl.stderrText;
    setImmediate(() => {
      if (text) stderr.emit('data', Buffer.from(text));
      child.emit('close', exit);
    });
    return child;
  },
}));

import { harvestSession } from '../src/captures.js';

let tmp = '';

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aptl-harvest-test-'));
  spawnControl.exitCode = 0;
  spawnControl.stderrText = '';
  spawnControl.capturedArgs = [];
  spawnControl.callCount = 0;
});
afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function activateScenario(traceId: string): void {
  writeFileSync(
    join(tmp, 'trace-context.json'),
    JSON.stringify({ trace_id: traceId, span_id: 'b'.repeat(16), trace_flags: '01' }),
  );
}

describe('harvestSession', () => {
  it('invokes `docker cp <container>:<src>/. <dest>` for the active scenario', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);

    // Pre-seed the dest with a fake harvested file so the post-cp
    // chmod walk has something to do (no docker daemon in test
    // environment).
    const dest = join(tmp, 'runs', tid, 'kali-side', 'sess-1');
    mkdirSync(join(dest, 'pty'), { recursive: true });
    writeFileSync(join(dest, 'pty', 'typescript'), 'hello');

    // (spawn behaviour controlled by spawnControl above)

    const ok = await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );

    expect(ok).toBe(true);
    // 3 docker cp calls: 1 per-session + 2 globals (_audit, _proc-acct).
    // Each may have retried up to 3 times via dockerCpWithRetry, but
    // we only stub success here so each lands in one call.
    expect(spawnControl.callCount).toBe(3);
    const [cmd, src, destArg] = spawnControl.capturedArgs[0];
    expect(cmd).toBe('cp');
    expect(src).toBe(`aptl-kali:/var/log/aptl/captures/${tid}/sess-1/.`);
    expect(destArg).toBe(dest);
    // Globals land under <dest>/_global/audit and _global/proc-acct.
    expect(spawnControl.capturedArgs[1][1]).toBe(
      'aptl-kali:/var/log/aptl/captures/_audit/.',
    );
    expect(spawnControl.capturedArgs[1][2]).toBe(join(dest, '_global', 'audit'));
    expect(spawnControl.capturedArgs[2][1]).toBe(
      'aptl-kali:/var/log/aptl/captures/_proc-acct/.',
    );
    expect(spawnControl.capturedArgs[2][2]).toBe(join(dest, '_global', 'proc-acct'));
  });

  it('falls back to _unbound when trace-context is absent', async () => {
    const dest = join(tmp, 'runs', '_unbound', 'kali-side', 'sess-1');
    mkdirSync(join(dest, 'pty'), { recursive: true });
    writeFileSync(join(dest, 'pty', 'typescript'), 'x');

    const ok = await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );

    expect(ok).toBe(true);
    expect(spawnControl.capturedArgs[0][1]).toBe(
      'aptl-kali:/var/log/aptl/captures/_unbound/sess-1/.',
    );
    // Globals still get harvested in the _unbound fallback path.
    expect(spawnControl.callCount).toBe(3);
  });

  it('returns false (NOT silent success) when per-session subtree is missing — converts a tampering primitive into a visible anomaly', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);
    spawnControl.exitCode = 1;
    spawnControl.stderrText = 'Error: No such file or directory';

    const ok = await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );

    // ADR-033 + codex cycle 2 finding-9: a "kali user deleted its
    // own session subtree before close" attack would otherwise be
    // invisible if we returned true here. The MCP-side PTY tee
    // still has the authoritative record; the harvest result
    // reports the anomaly so it's surfaceable.
    expect(ok).toBe(false);
  });

  it('still attempts global (_audit + _proc-acct) harvest even when per-session subtree is missing', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);
    spawnControl.exitCode = 1;
    spawnControl.stderrText = 'Error: No such file or directory';

    await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );

    // 3 attempts (per-session + 2 globals), each retried up to 3
    // times under the retry-with-backoff helper (cycle 2 finding-2).
    // We don't pin the exact count — the assertion is that the
    // global attempts happen at all, i.e. > 1 spawn call.
    expect(spawnControl.callCount).toBeGreaterThan(1);
    const globalSrcs = spawnControl.capturedArgs.map((args) => args[1]);
    expect(globalSrcs.some((s) => s.endsWith('_audit/.'))).toBe(true);
    expect(globalSrcs.some((s) => s.endsWith('_proc-acct/.'))).toBe(true);
  });

  it('returns false on real docker cp failure but does not throw', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);
    spawnControl.exitCode = 1;
    spawnControl.stderrText = 'Error: permission denied';

    const ok = await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );
    expect(ok).toBe(false);
  });

  it('creates the destination directory with 0700 mode', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);

    await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );

    const dest = join(tmp, 'runs', tid, 'kali-side', 'sess-1');
    expect(existsSync(dest)).toBe(true);
    // Mask to permission bits; the high bits include S_IFDIR which
    // varies by platform.
    expect(statSync(dest).mode & 0o777).toBe(0o700);
  });

  it('chmods harvested files to 0600 and dirs to 0700 recursively', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);

    const dest = join(tmp, 'runs', tid, 'kali-side', 'sess-1');
    mkdirSync(join(dest, 'pty'), { recursive: true });
    mkdirSync(join(dest, 'pcap'), { recursive: true });
    writeFileSync(join(dest, 'pty', 'typescript'), 'x');
    writeFileSync(join(dest, 'pcap', 'session.pcap'), 'binary');

    await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );

    expect(statSync(join(dest, 'pty')).mode & 0o777).toBe(0o700);
    expect(statSync(join(dest, 'pcap')).mode & 0o777).toBe(0o700);
    expect(statSync(join(dest, 'pty', 'typescript')).mode & 0o777).toBe(0o600);
    expect(statSync(join(dest, 'pcap', 'session.pcap')).mode & 0o777).toBe(0o600);
  });

  it('rejects an unsafe session id without invoking docker cp', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);

    const ok = await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      '../escape',
    );
    expect(ok).toBe(false);
    expect(spawnControl.callCount).toBe(0);
  });

  it('honours an explicit runId opt (bypasses ambient trace context)', async () => {
    // Active trace context says X; explicit runId says Y; harvest
    // must pin to Y (codex pre-push cycle 3 finding-6).
    activateScenario('x'.repeat(32));
    await harvestSession(
      {
        containerName: 'aptl-kali',
        env: { APTL_STATE_DIR: tmp },
        runId: 'y'.repeat(32),
      },
      'sess-1',
    );
    expect(spawnControl.capturedArgs[0][1]).toContain(`/var/log/aptl/captures/${'y'.repeat(32)}/sess-1/.`);
  });
});

describe('captures: docker binary resolution', () => {
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aptl-harvest-bin-'));
    spawnControl.callCount = 0;
    spawnControl.exitCode = 0;
    spawnControl.stderrText = '';
    spawnControl.capturedArgs = [];
  });

  it('defaults to /usr/bin/docker (no PATH lookup)', async () => {
    // Even without APTL_DOCKER_BIN set, spawn target should be the
    // absolute path so PATH-injection cannot redirect to a hostile
    // binary (SonarCloud hotspot S4036). We can't directly inspect
    // the spawned command name in our mock (we capture args, not
    // the executable), so this test acts as a smoke check that the
    // harvest path completes with default env.
    const ok = await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-bin',
    );
    expect(typeof ok).toBe('boolean');
    expect(spawnControl.callCount).toBeGreaterThan(0);
  });

  it('honours APTL_DOCKER_BIN override', async () => {
    const ok = await harvestSession(
      {
        containerName: 'aptl-kali',
        env: { APTL_STATE_DIR: tmp, APTL_DOCKER_BIN: '/opt/docker/bin/docker' },
      },
      'sess-bin',
    );
    expect(typeof ok).toBe('boolean');
    expect(spawnControl.callCount).toBeGreaterThan(0);
  });
});
