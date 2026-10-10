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
  cpSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readFileSync,
  statSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';

type DockerResult = { code: number; stderr: string };

// Module-level controls the mocked `spawn` reads on every invocation.
// Each test resets them in `beforeEach`.
interface SpawnControl {
  exitCode: number;
  stderrText: string;
  capturedArgs: string[][];
  capturedCmds: string[];
  callCount: number;
  /** When set, replay recorded results keyed by the `<container>:<src>` arg. */
  recorded?: Record<string, DockerResult>;
  /** When set, `docker cp` reads from `root` as the filesystem of `name`. */
  container?: { name: string; root: string };
}
const spawnControl: SpawnControl = {
  exitCode: 0,
  stderrText: '',
  capturedArgs: [],
  capturedCmds: [],
  callCount: 0,
};

/** Replay one recorded result; an unrecorded argv fails loudly (rc 125). */
function replay(args: string[]): DockerResult {
  if (spawnControl.container) return copyFromContainer(spawnControl.container, args);
  if (!spawnControl.recorded) {
    return { code: spawnControl.exitCode, stderr: spawnControl.stderrText };
  }
  return spawnControl.recorded[args[1]] ?? { code: 125, stderr: `unrecorded: ${args[1]}` };
}

/** `docker cp <name>:<dir>/. <dest>` against a directory standing in for the container. */
function copyFromContainer(container: { name: string; root: string }, args: string[]): DockerResult {
  const [, source, dest] = args;
  const name = source.slice(0, source.indexOf(':'));
  const path = source.slice(name.length + 1);
  if (name !== container.name) return noSuchContainer(name);
  const local = join(container.root, path);
  if (!existsSync(local)) return missingFile(name, path);
  cpSync(local, dest, { recursive: true });
  return { code: 0, stderr: '' };
}

// #1242: `docker cp` replies recorded on 2026-10-09 UTC against Docker CLI and
// Engine 29.7.2 (API 1.55), with stdout and stderr piped as `execDockerCp`
// spawns them. A created, never-started `FROM scratch` container named
// `aptl-w123456789abc-kali-capture` copied a present path with exit 0 and no
// output, and answered a missing one with the `Could not find the file` line
// below. With no such container, the daemon answered every path with the same
// `No such container` line.
const SCOPED = 'aptl-w123456789abc-kali-capture';
const FIXED = 'aptl-kali-capture';
const ROOT = '/var/log/aptl/captures';
const RUN = 'a'.repeat(32);
const missingFile = (name: string, path: string): DockerResult => ({
  code: 1,
  stderr: `Error response from daemon: Could not find the file ${path} in container ${name}\n`,
});
const noSuchContainer = (name: string): DockerResult => ({
  code: 1,
  stderr: `Error response from daemon: No such container: ${name}\n`,
});
const absent = (name: string): Record<string, DockerResult> =>
  Object.fromEntries(
    [`${RUN}/sessions/sess-1/.`, '_audit/.', '_proc-acct/.'].map((path) => [
      `${name}:${ROOT}/${path}`,
      noSuchContainer(name),
    ]),
  );
const RECORDED_DOCKER_CP = {
  scopedAbsent: absent(SCOPED),
  fixedAbsent: absent(FIXED),
};

// One session as containers/kali-capture/broker.py records it: the frames and
// metadata under `<root>/<run>/sessions/<session>/`, and the run's ledger of
// accepted sessions beside `sessions/`.
const FRAMES =
  '{"data_b64":"aGVsbG8K","direction":"output","sequence":1,"timestamp":"2026-10-09T00:00:01Z"}\n';
const METADATA = '{"close_reason":"clean-exit","frame_count":1,"session_id":"sess-1"}';

vi.mock('node:child_process', () => ({
  spawn: (cmd: string, args: string[]) => {
    spawnControl.callCount += 1;
    // Test-quality review cycle 1 T-001/T-002: capture the spawned
    // binary path so SonarCloud S4036 hardening (the "no PATH lookup"
    // contract) is actually pinned. Previously the mock discarded
    // `_cmd`, so both `dockerBin()` regressions (default-vs-override)
    // and "harvest stopped using docker at all" regressions would
    // pass vacuously.
    spawnControl.capturedCmds.push(cmd);
    spawnControl.capturedArgs.push(args);
    const stdout = new EventEmitter();
    const stderr = new EventEmitter();
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
    };
    child.stdout = stdout;
    child.stderr = stderr;
    const { code: exit, stderr: text } = replay(args);
    setImmediate(() => {
      if (text) stderr.emit('data', Buffer.from(text));
      child.emit('close', exit);
    });
    return child;
  },
}));

import { harvestSession } from '../src/captures.js';
import { loadLabConfig } from '../src/config.js';
import { resolveCaptureContainer } from '../src/tools/handlers.js';

// tests/ -> aptl-mcp-common/ -> mcp/, then the shipped red server config.
const RED_CONFIG = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'mcp-red',
  'docker-lab-config.json',
);

let tmp = '';

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aptl-harvest-test-'));
  spawnControl.exitCode = 0;
  spawnControl.stderrText = '';
  spawnControl.capturedArgs = [];
  spawnControl.capturedCmds = [];
  spawnControl.callCount = 0;
  spawnControl.recorded = undefined;
  spawnControl.container = undefined;
});
afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(tmp, { recursive: true, force: true });
});

function activateScenario(traceId: string): void {
  writeFileSync(
    join(tmp, 'trace-context.json'),
    JSON.stringify({ trace_id: traceId, span_id: 'b'.repeat(16), trace_flags: '01' }),
  );
}

describe('harvestSession', () => {
  it('harvests into the configured Python run archive', async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);
    const archive = join(tmp, 'archive');
    const dest = join(archive, tid, 'kali-side', 'sess-1');
    mkdirSync(join(dest, 'pty'), { recursive: true });
    writeFileSync(join(dest, 'pty', 'typescript'), 'hello');

    const ok = await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp, APTL_MCP_RUN_STORE_BASE: archive } },
      'sess-1',
    );

    expect(ok).toBe(true);
    expect(spawnControl.capturedArgs[0][2]).toBe(dest);
  });
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
    expect(src).toBe(`aptl-kali:/var/log/aptl/captures/${tid}/sessions/sess-1/.`);
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
      'aptl-kali:/var/log/aptl/captures/_unbound/sessions/sess-1/.',
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

    // #304: retry helper removed — remote close is now awaited in
    // PersistentSession.close before harvest runs, so the 250ms x 3
    // backoff window is no longer needed. Exactly 3 docker cp calls:
    // 1 per-session + 2 globals (_audit, _proc-acct), no retries.
    expect(spawnControl.callCount).toBe(3);
    const globalSrcs = spawnControl.capturedArgs.map((args) => args[1]);
    expect(globalSrcs.some((s) => s.endsWith('_audit/.'))).toBe(true);
    expect(globalSrcs.some((s) => s.endsWith('_proc-acct/.'))).toBe(true);
  });

  it("#304: per-session docker cp failure invokes spawn exactly once (no retry-with-backoff)", async () => {
    const tid = 'a'.repeat(32);
    activateScenario(tid);
    spawnControl.exitCode = 1;
    spawnControl.stderrText = 'Error: No such file or directory';

    await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-1',
    );

    // First call is the per-session attempt; the next two are globals.
    // With the retry helper removed, the per-session "no such file"
    // failure is NOT retried — it fails fast and harvest moves on.
    const perSessionSrc = `aptl-kali:/var/log/aptl/captures/${tid}/sessions/sess-1/.`;
    const perSessionCalls = spawnControl.capturedArgs.filter(
      (args) => args[1] === perSessionSrc,
    );
    expect(perSessionCalls.length).toBe(1);
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
    expect(spawnControl.capturedArgs[0][1]).toContain(`/var/log/aptl/captures/${'y'.repeat(32)}/sessions/sess-1/.`);
  });
});

describe('#1242: workspace-scoped capture container (recorded docker cp)', () => {
  const sessionDir = (session: string) => join(tmp, 'runs', RUN, 'kali-side', session);
  const failureRecord = (session: string) =>
    join(sessionDir(session), 'capture-harvest-failure.json');
  const harvest = (containerName: string, session = 'sess-1') =>
    harvestSession({ containerName, env: { APTL_STATE_DIR: tmp } }, session);
  /** Stand in for the sidecar `name` after the broker recorded `session`. */
  const brokerContainer = (name: string, session: string) => {
    const root = join(tmp, 'container');
    const runRoot = join(root, ROOT, RUN);
    mkdirSync(join(runRoot, 'sessions', session), { recursive: true });
    writeFileSync(join(runRoot, 'accepted-sessions.jsonl'), `{"session_id":"${session}"}\n`);
    writeFileSync(join(runRoot, 'sessions', session, 'frames.jsonl'), FRAMES);
    writeFileSync(join(runRoot, 'sessions', session, 'metadata.json'), METADATA);
    spawnControl.container = { name, root };
  };

  beforeEach(() => activateScenario(RUN));

  it('harvests from the sidecar name lab start injects into the shipped red config', async () => {
    vi.stubEnv('APTL_MCP_DISABLE_DOTENV', '1');
    vi.stubEnv('LILRAE_MCP_CAPTURE_CONTAINER', SCOPED);
    brokerContainer(SCOPED, 'sess-1');
    const containerName = resolveCaptureContainer(await loadLabConfig(RED_CONFIG));
    expect(containerName).toBe(SCOPED);

    expect(await harvest(containerName as string)).toBe(true);
    expect(spawnControl.capturedArgs[0]).toEqual([
      'cp',
      `${SCOPED}:${ROOT}/${RUN}/sessions/sess-1/.`,
      sessionDir('sess-1'),
    ]);
    expect(existsSync(failureRecord('sess-1'))).toBe(false);
  });

  it('copies the session files the capture broker writes into the run evidence', async () => {
    brokerContainer(SCOPED, 'sess-1');

    expect(await harvest(SCOPED)).toBe(true);
    expect(readFileSync(join(sessionDir('sess-1'), 'frames.jsonl'), 'utf-8')).toBe(FRAMES);
    expect(readFileSync(join(sessionDir('sess-1'), 'metadata.json'), 'utf-8')).toBe(METADATA);
    // The run's ledger of accepted sessions stays out of one session's evidence.
    expect(existsSync(join(sessionDir('sess-1'), 'accepted-sessions.jsonl'))).toBe(false);
  });

  it.each([
    ['workspace-scoped', SCOPED, RECORDED_DOCKER_CP.scopedAbsent],
    ['fixed legacy', FIXED, RECORDED_DOCKER_CP.fixedAbsent],
  ])('records a named failure in run evidence when the %s container is missing', async (_kind, name, recorded) => {
    spawnControl.recorded = recorded;

    expect(await harvest(name)).toBe(false);
    expect(JSON.parse(readFileSync(failureRecord('sess-1'), 'utf-8'))).toEqual({
      failure: 'aptl.capture-harvest.container-missing',
      container: name,
      run_id: RUN,
      session_id: 'sess-1',
      recorded_at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
    });
    expect(statSync(failureRecord('sess-1')).mode & 0o777).toBe(0o600);
    // ADR-042: the global `_audit` / `_proc-acct` harvest is still attempted.
    expect(spawnControl.callCount).toBe(3);
  });

  it('keeps a missing per-session subtree distinct from a missing container', async () => {
    brokerContainer(SCOPED, 'sess-1');

    expect(await harvest(SCOPED, 'sess-gone')).toBe(false);
    expect(existsSync(failureRecord('sess-gone'))).toBe(false);
  });

  it('never writes through a link already at the failure record path', async () => {
    spawnControl.recorded = RECORDED_DOCKER_CP.scopedAbsent;
    const outside = join(tmp, 'outside.txt');
    writeFileSync(outside, 'untouched');
    mkdirSync(sessionDir('sess-1'), { recursive: true });
    symlinkSync(outside, failureRecord('sess-1'));

    expect(await harvest(SCOPED)).toBe(false);
    expect(readFileSync(outside, 'utf-8')).toBe('untouched');
  });
});

describe('captures: docker binary resolution', () => {
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aptl-harvest-bin-'));
    spawnControl.callCount = 0;
    spawnControl.exitCode = 0;
    spawnControl.stderrText = '';
    spawnControl.capturedArgs = [];
    spawnControl.capturedCmds = [];
  });

  it('defaults to /usr/bin/docker (no PATH lookup)', async () => {
    // Without APTL_DOCKER_BIN set, the spawned binary must be the
    // absolute /usr/bin/docker so PATH-injection cannot redirect to
    // a hostile binary (SonarCloud hotspot S4036). Test-quality
    // review cycle 1 T-001: the mock now captures the spawned cmd
    // (previously discarded), so a regression in `dockerBin()` —
    // e.g., returning plain `'docker'` — fails this test.
    await harvestSession(
      { containerName: 'aptl-kali', env: { APTL_STATE_DIR: tmp } },
      'sess-bin',
    );
    expect(spawnControl.callCount).toBeGreaterThan(0);
    expect(spawnControl.capturedCmds[0]).toBe('/usr/bin/docker');
    // Every subsequent spawn (globals harvest) must use the same path.
    for (const cmd of spawnControl.capturedCmds) {
      expect(cmd).toBe('/usr/bin/docker');
    }
  });

  it('honours APTL_DOCKER_BIN override', async () => {
    // Test-quality review cycle 1 T-002: previously this test could
    // not observe whether APTL_DOCKER_BIN was actually consumed —
    // the mock discarded `_cmd`. With cmd capture in place, a
    // regression that ignores the env override fails this test.
    await harvestSession(
      {
        containerName: 'aptl-kali',
        env: { APTL_STATE_DIR: tmp, APTL_DOCKER_BIN: '/opt/docker/bin/docker' },
      },
      'sess-bin',
    );
    expect(spawnControl.callCount).toBeGreaterThan(0);
    expect(spawnControl.capturedCmds[0]).toBe('/opt/docker/bin/docker');
    for (const cmd of spawnControl.capturedCmds) {
      expect(cmd).toBe('/opt/docker/bin/docker');
    }
  });
});
