/**
 * Per-session capture harvest from the Kali capture sidecar.
 *
 * OBS-003 / ADR-033 / ADR-041 design: the `aptl-kali-capture` sidecar (not the
 * Kali workload) writes per-session captures (PTY typescript, pcap,
 * audit/proc-acct snapshots) into a docker named volume at
 * `/var/log/aptl/captures/<run_id>/<session_id>/`. The Kali workload does not
 * mount the volume at all, so a sudo-capable agent cannot read or tamper with
 * evidence (ADR-041). The volume is invisible to the host filesystem to
 * prevent cross-scenario tampering (codex pre-push cycle 1 finding-10).
 *
 * When an SSH session closes, the MCP server invokes `harvestSession()` which
 * runs `docker cp` against the capture container (the sidecar — see
 * `resolveCaptureContainer` / `capture_container_name`) to copy the
 * per-session subtree out into `.aptl/runs/<run_id>/kali-side/<session_id>/`
 * on the host, then sets 0600 permissions on every file. The harvest is
 * best-effort — a missing container / docker / missing subdir logs to stderr
 * but does not throw out of the close path.
 */

import { spawn } from 'node:child_process';
import { chmod, mkdir, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { kaliSideSessionDir, loadActiveTraceId } from './runs.js';

export interface HarvestOptions {
  /** Docker container to harvest from. Per ADR-041 this is the capture
   * sidecar (e.g. `aptl-kali-capture`), which owns the captures volume. */
  containerName: string;
  /** Path inside the container that holds per-run capture subdirs.
   * Defaults to `/var/log/aptl/captures` to match the wrapper. */
  containerCapturesRoot?: string;
  /** APTL state directory on the host (defaults to `APTL_STATE_DIR`
   * env var or `.aptl`). */
  stateDir?: string;
  /** Env to pass through; used for testability. */
  env?: NodeJS.ProcessEnv;
  /** Bind harvest to a specific run id rather than re-reading the
   * active trace context. Set when a long-running session captured
   * its run_id at open time and the active trace context may have
   * rotated since (codex pre-push cycle 3 finding-6). */
  runId?: string;
}

const DEFAULT_CONTAINER_CAPTURES_ROOT = '/var/log/aptl/captures';

// Override via `APTL_DOCKER_BIN` for non-standard installations.
// Default to the standard absolute path so the spawn does NOT rely
// on PATH lookup (SonarCloud hotspot captures.ts:47 — a writable
// PATH directory could otherwise execute an attacker-controlled
// `docker`). Falls back to plain `docker` only when the absolute
// path is missing AND the env override is unset; in that case the
// developer is expected to have a controlled PATH.
const DEFAULT_DOCKER_BIN = '/usr/bin/docker';

function dockerBin(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.APTL_DOCKER_BIN;
  if (override && override.length > 0) return override;
  return DEFAULT_DOCKER_BIN;
}

function execDockerCp(
  args: string[],
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ code: number; stderr: string }> {
  // Thread the caller's env through so APTL_DOCKER_BIN overrides set on
  // HarvestOptions actually reach dockerBin(). Without this, the test
  // mock could not observe the override and the SonarCloud S4036
  // "no PATH lookup" contract was unverifiable. (Test-quality review
  // cycle 1 T-002.)
  return new Promise((res) => {
    const child = spawn(dockerBin(env), args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (b) => {
      stderr += b.toString();
    });
    child.on('error', (err) => {
      res({ code: -1, stderr: String(err) });
    });
    child.on('close', (code) => {
      res({ code: code ?? -1, stderr });
    });
  });
}

async function chmodTreeBestEffort(root: string, fileMode: number, dirMode: number): Promise<void> {
  // Recursively chmod every file/dir under root. Best-effort: a
  // missing path or permission denied is logged, not thrown.
  try {
    const entries = await readdir(root, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(root, entry.name);
      try {
        if (entry.isDirectory()) {
          await chmod(full, dirMode);
          await chmodTreeBestEffort(full, fileMode, dirMode);
        } else {
          await chmod(full, fileMode);
        }
      } catch (err) {
        console.error(`[captures] chmod ${full} failed:`, err);
      }
    }
  } catch (err) {
    console.error(`[captures] readdir ${root} failed:`, err);
  }
}

interface ResolvedHarvestParams {
  env: NodeJS.ProcessEnv;
  stateDir: string;
  containerCapturesRoot: string;
  tid: string;
}

/**
 * Resolve the effective env, state dir, container captures root, and run id
 * for a harvest. Run id resolution: explicit `opts.runId` wins (passed by
 * persistent-session callers that captured the active trace at session open
 * time), otherwise re-read the current trace context, falling back to
 * `_unbound` so harvests outside a scenario context still land somewhere
 * predictable.
 */
function resolveHarvestParams(opts: HarvestOptions): ResolvedHarvestParams {
  const env = opts.env ?? process.env;
  return {
    env,
    stateDir: opts.stateDir ?? env.APTL_STATE_DIR ?? '.aptl',
    containerCapturesRoot: opts.containerCapturesRoot ?? DEFAULT_CONTAINER_CAPTURES_ROOT,
    tid: opts.runId ?? loadActiveTraceId(env) ?? '_unbound',
  };
}

/**
 * Copy one session's per-session capture subtree out of the container.
 * Returns `false` (and logs) when docker cp failed for a reason worth
 * surfacing, including a missing source subtree; `true` on success or a clean
 * no-op.
 */
async function copyPerSessionCaptures(
  containerName: string,
  src: string,
  destDir: string,
  env: NodeJS.ProcessEnv,
  sessionId: string,
): Promise<boolean> {
  const cpResult = await execDockerCp(['cp', `${containerName}:${src}`, destDir], env);
  if (cpResult.code === 0) return true;
  if (
    /No such file or directory/i.test(cpResult.stderr) ||
    /Could not find the file/i.test(cpResult.stderr)
  ) {
    // Surface the missing-source case loudly. ADR-033 + codex
    // cycle 2 finding-9: with the kali user owning the capture
    // subtree, an attacker who deletes their own session dir
    // before close can wipe the Kali-side captures. Silent
    // success would convert that tampering into invisible data
    // loss. We log + return false so the operator sees a real
    // anomaly. The MCP-side PTY tee and tool-call JSONL remain
    // as the independent (and tamper-resistant) record.
    console.error(
      `[captures] per-session subtree missing for ${sessionId}; expected at ${src}. ` +
        'MCP-side captures remain in `.aptl/runs/<run>/mcp-side/`.',
    );
  } else {
    console.error(
      `[captures] docker cp failed (rc=${cpResult.code}):`,
      cpResult.stderr.trim(),
    );
  }
  return false;
}

/**
 * Pull container-wide capture roots (auditd log + process accounting pacct)
 * into `<destDir>/_global/`. These are scenario-wide and useful even when the
 * per-session subtree is missing — they may explain WHY it is gone.
 * Best-effort: logs but never fails the harvest.
 */
async function harvestGlobalCaptures(
  containerName: string,
  containerCapturesRoot: string,
  destDir: string,
  env: NodeJS.ProcessEnv,
): Promise<void> {
  const globalDest = join(destDir, '_global');
  try {
    await mkdir(globalDest, { recursive: true, mode: 0o700 });
  } catch (err) {
    console.error('[captures] mkdir _global failed:', err);
  }
  for (const globalSub of ['_audit', '_proc-acct']) {
    const globalSrc = `${containerCapturesRoot}/${globalSub}/.`;
    const gRes = await execDockerCp(
      [
        'cp',
        `${containerName}:${globalSrc}`,
        join(globalDest, globalSub.replace(/^_/, '')),
      ],
      env,
    );
    if (gRes.code !== 0 && !/No such file or directory/i.test(gRes.stderr)) {
      console.error(
        `[captures] global ${globalSub} harvest failed (rc=${gRes.code}):`,
        gRes.stderr.trim(),
      );
    }
  }
}

/**
 * Verify destDir actually has content and chmod everything to 0600. Returns
 * `perSessionOk` on success, or false when the destination is missing.
 */
async function finalizeHarvest(destDir: string, perSessionOk: boolean): Promise<boolean> {
  try {
    const st = await stat(destDir);
    if (!st.isDirectory()) return false;
  } catch {
    return false;
  }
  await chmodTreeBestEffort(destDir, 0o600, 0o700);
  return perSessionOk;
}

/**
 * Harvest one session's captures out of the Kali container into
 * the host-side per-run directory.
 *
 * Returns `true` when the copy completed (or there was nothing to
 * copy — clean no-op), `false` when docker cp failed for a reason
 * worth surfacing. Never throws.
 */
export async function harvestSession(opts: HarvestOptions, sessionId: string): Promise<boolean> {
  const { env, stateDir, containerCapturesRoot, tid } = resolveHarvestParams(opts);

  let destDir: string;
  try {
    destDir = kaliSideSessionDir(stateDir, tid, sessionId);
  } catch (err) {
    console.error('[captures] invalid run/session id; skipping harvest:', err);
    return false;
  }

  try {
    await mkdir(destDir, { recursive: true, mode: 0o700 });
  } catch (err) {
    console.error('[captures] mkdir destDir failed:', err);
    return false;
  }

  // `docker cp <container>:<src>/. <dest>` copies the CONTENTS of src
  // into dest. The trailing `/.` is important — without it docker cp
  // copies the source directory itself into dest, producing
  // dest/<session_id>/... which would nest one level too deep.
  const src = `${containerCapturesRoot}/${tid}/${sessionId}/.`;
  // Track whether the per-session subtree was actually copied — even
  // on a "not found" no-op, we still attempt the global captures
  // harvest below (codex cycle 2 finding-6).
  const perSessionOk = await copyPerSessionCaptures(
    opts.containerName,
    src,
    destDir,
    env,
    sessionId,
  );

  await harvestGlobalCaptures(opts.containerName, containerCapturesRoot, destDir, env);

  return finalizeHarvest(destDir, perSessionOk);
}
