/**
 * Per-session capture harvest from the Kali container.
 *
 * OBS-003 / ADR-033 design: the Kali container writes per-session
 * captures (PTY typescript+timing, pcap, audit/proc-acct snapshots)
 * into a docker named volume at `/var/log/aptl/captures/<run_id>/<session_id>/`.
 * The volume is invisible to the host filesystem to prevent cross-
 * scenario tampering by the kali user (codex pre-push cycle 1
 * finding-10).
 *
 * When an SSH session closes, the MCP server invokes
 * `harvestSession()` which runs `docker cp` to copy the per-session
 * subtree out into `.aptl/runs/<run_id>/kali-side/<session_id>/`
 * on the host, then sets 0600 permissions on every file. The
 * harvest is best-effort — a missing container / docker / missing
 * subdir logs to stderr but does not throw out of the close path.
 */

import { spawn } from 'node:child_process';
import { chmod, mkdir, readdir, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';

import { kaliSideSessionDir, resolveActiveRunDir, loadActiveTraceId } from './runs.js';

export interface HarvestOptions {
  /** Docker container to harvest from (e.g. `aptl-kali`). */
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

function execDockerCp(args: string[]): Promise<{ code: number; stderr: string }> {
  return new Promise((res) => {
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
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

const HARVEST_RETRIES = 3;
const HARVEST_BACKOFF_MS = 250;

/**
 * Run `docker cp` with bounded retries. The MCP-side `closeSession`
 * returns as soon as `shell.end()` resolves locally, but the remote
 * SSH channel close (which fires the Kali wrapper's EXIT trap that
 * kills tcpdump and flushes the script typescript) can take a few
 * hundred milliseconds longer (codex cycle 2 finding-2). Without a
 * retry the harvest can race the cleanup and copy a truncated or
 * partially-flushed tree. The retry isn't a correctness substitute
 * for awaiting remote-close — see the SSH layer for that work — but
 * it makes the practical case land cleanly.
 */
async function dockerCpWithRetry(args: string[]): Promise<{ code: number; stderr: string }> {
  let last = await execDockerCp(args);
  for (let attempt = 1; attempt < HARVEST_RETRIES; attempt += 1) {
    // Retry on docker-side transient failures and on
    // "No such file" (the typical "wrapper not finished" symptom).
    if (last.code === 0) return last;
    if (/No such file or directory/i.test(last.stderr) || last.code === 1) {
      await new Promise((r) => setTimeout(r, HARVEST_BACKOFF_MS * attempt));
      last = await execDockerCp(args);
      continue;
    }
    break;
  }
  return last;
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

/**
 * Harvest one session's captures out of the Kali container into
 * the host-side per-run directory.
 *
 * Returns `true` when the copy completed (or there was nothing to
 * copy — clean no-op), `false` when docker cp failed for a reason
 * worth surfacing. Never throws.
 */
export async function harvestSession(opts: HarvestOptions, sessionId: string): Promise<boolean> {
  const env = opts.env ?? process.env;
  const stateDir = opts.stateDir ?? env.APTL_STATE_DIR ?? '.aptl';
  const containerCapturesRoot = opts.containerCapturesRoot ?? DEFAULT_CONTAINER_CAPTURES_ROOT;

  // Resolve the run id: explicit `opts.runId` wins (passed by
  // persistent-session callers that captured the active trace at
  // session open time), otherwise re-read the current trace
  // context, falling back to `_unbound` so harvests outside a
  // scenario context still land somewhere predictable.
  const tid = opts.runId ?? loadActiveTraceId(env) ?? '_unbound';
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
  const cpResult = await dockerCpWithRetry([
    'cp',
    `${opts.containerName}:${src}`,
    destDir,
  ]);
  // Track whether the per-session subtree was actually copied — even
  // on a "not found" no-op, we still want to attempt the global
  // captures harvest below (codex cycle 2 finding-6).
  let perSessionOk = true;
  if (cpResult.code !== 0) {
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
      perSessionOk = false;
    } else {
      console.error(
        `[captures] docker cp failed (rc=${cpResult.code}):`,
        cpResult.stderr.trim(),
      );
      perSessionOk = false;
    }
  }

  // Always attempt to pull container-wide capture roots (auditd log
  // + process accounting pacct) into `<dest>/_global/`. These are
  // scenario-wide and useful even when the per-session subtree is
  // missing — they may explain WHY the per-session subtree is gone.
  const globalDest = join(destDir, '_global');
  try {
    await mkdir(globalDest, { recursive: true, mode: 0o700 });
  } catch (err) {
    console.error('[captures] mkdir _global failed:', err);
  }
  for (const globalSub of ['_audit', '_proc-acct']) {
    const globalSrc = `${containerCapturesRoot}/${globalSub}/.`;
    const gRes = await dockerCpWithRetry([
      'cp',
      `${opts.containerName}:${globalSrc}`,
      join(globalDest, globalSub.replace(/^_/, '')),
    ]);
    if (gRes.code !== 0 && !/No such file or directory/i.test(gRes.stderr)) {
      console.error(
        `[captures] global ${globalSub} harvest failed (rc=${gRes.code}):`,
        gRes.stderr.trim(),
      );
    }
  }

  // Verify destDir actually has content and chmod everything to 0600.
  try {
    const st = await stat(destDir);
    if (!st.isDirectory()) return false;
  } catch {
    return false;
  }
  await chmodTreeBestEffort(destDir, 0o600, 0o700);
  return perSessionOk;
}
