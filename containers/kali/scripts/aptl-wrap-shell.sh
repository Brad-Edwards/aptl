#!/bin/bash
# OBS-003 / ADR-033 per-session shell wrapper invoked by sshd's
# ForceCommand. Captures the full PTY (every keystroke + every byte of
# output, with timing) via script(1), starts a per-session tcpdump,
# then runs the agent's command (or an interactive bash). All
# captures land under
#   /var/log/aptl/captures/<run_id>/<session_id>/
# inside the container. The MCP server harvests them out via
# `docker cp` on session close (see captures.ts) into the host's
# `.aptl/runs/<run_id>/kali-side/<session_id>/`. The container holds
# captures in a docker named volume (not a host bind mount), so the
# kali user cannot read or tamper with prior runs' MCP-side records
# (codex pre-push cycle 1 finding-10).
#
# Hardening notes addressed in this revision:
#   - cycle 1 finding-7: do NOT `exec` script — run it as a child so
#     the EXIT trap still fires and kills tcpdump.
#   - cycle 1 finding-11: enforce 0700 dirs / 0600 files via umask.
#   - cycle 1 finding-13: reject IDs containing `.` `..` or any
#     character outside [A-Za-z0-9_-]; fall back to a generated safe
#     ID rather than absorbing the value.
#
# Best-effort: if setup fails (missing script/tcpdump, capture dir
# can't be created), log a warning and exec the requested shell
# unwrapped rather than break SSH login.

set -u
umask 077

# ID validation MUST match the canonical contract used by the
# Python `src/aptl/core/runstore.py` `_ID_RE` and the TypeScript
# `mcp/aptl-mcp-common/src/runs.ts` `ID_RE` (codex pre-push cycle 2
# finding-4 + finding-10): any divergence causes the wrapper to
# silently re-route an MCP-allowed id (e.g. `_unbound`, `foo.bar`)
# into `anon-...`, and the MCP-side `harvestSession()` then looks
# under the originally-requested path, finds nothing, and reports
# success — silently losing all Kali-side captures for that session
# (also turns into a tampering primitive if an agent picks
# `evade.harvest` as their session id).
#
# Canonical rule: `^[A-Za-z0-9_][A-Za-z0-9._-]*$` AND must not
# contain `..`. Leading `_` permitted so the `_unbound` sentinel
# round-trips; `.` permitted so version-shaped ids like `sess-1.0`
# round-trip; `..` rejected as the only real path-traversal vector.
valid_id() {
  case "$1" in
    *..* | */* | "" ) return 1 ;;
    *) ;;
  esac
  printf '%s' "$1" | LC_ALL=C grep -Eq '^[A-Za-z0-9_][A-Za-z0-9._-]*$'
}

safe_id() {
  local raw="${1:-}"
  if valid_id "$raw"; then
    printf '%s' "$raw"
  else
    printf 'anon-%s-%s' "$(date +%s)" "$$"
  fi
}

SESSION_ID="$(safe_id "${APTL_SESSION_ID:-}")"
RUN_ID="$(safe_id "${APTL_RUN_ID:-_unbound}")"

SESS_DIR="/var/log/aptl/captures/${RUN_ID}/${SESSION_ID}"

run_unwrapped() {
  if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
  fi
  exec /bin/bash --login
}

if ! mkdir -p "$SESS_DIR/pty" "$SESS_DIR/pcap" 2>/dev/null; then
  echo "[aptl-wrap-shell] capture dir setup failed; running unwrapped" >&2
  run_unwrapped
fi
# Tighten perms on the per-session subtree (umask covered new
# directories, but be explicit so a re-run after a chmod doesn't
# leave a wider parent).
chmod 0700 "$SESS_DIR" "$SESS_DIR/pty" "$SESS_DIR/pcap" 2>/dev/null || true

PTY_TS="$SESS_DIR/pty/typescript"
PTY_TIMING="$SESS_DIR/pty/timing"
PCAP="$SESS_DIR/pcap/session.pcap"

TCPDUMP_PID=""
if command -v tcpdump >/dev/null 2>&1; then
  # -C 100M, -W 10 → rolling 1GB max per session so an agent cannot
  # fill the host disk with one long-running session. tcpdump runs
  # with cap_net_raw+cap_net_admin via file capabilities applied in
  # the Dockerfile (codex cycle 1 finding-6), so no sudo / no root.
  # `not port 22` filters out SSH noise so the pcap is small enough
  # to be tractable per session.
  tcpdump -i any -w "$PCAP" -C 100 -W 10 -U \
    not port 22 \
    >/dev/null 2>&1 &
  TCPDUMP_PID=$!
fi

cleanup() {
  if [ -n "$TCPDUMP_PID" ]; then
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
  fi
  # Repair file modes one more time at exit — script writes the
  # typescript / timing files with the wrapper's umask, but a
  # bare-metal `chmod` here closes any residual race window.
  chmod 0600 "$PTY_TS" "$PTY_TIMING" 2>/dev/null || true
  find "$SESS_DIR/pcap" -type f -name '*.pcap*' -exec chmod 0600 {} + 2>/dev/null || true
}
trap cleanup EXIT TERM INT

if ! command -v script >/dev/null 2>&1; then
  echo "[aptl-wrap-shell] script(1) missing; running unwrapped" >&2
  run_unwrapped
fi

# `script -q` suppresses the "Script started" banner; `-f` flushes
# after each write so a killed session preserves the tail; `--timing`
# writes a side file so playback is possible later. `--return` makes
# script(1) propagate the wrapped command's exit status — without it
# script returns its own status (0 on clean disconnect) and a failing
# command like `false` would close the SSH channel with rc=0,
# breaking `kali_run_command` result semantics and OCSF outcome
# derivation (codex cycle 2 finding-1). `--log-io` writes a single
# combined input+output transcript (replaces `--command`'s
# output-only capture) so non-echoed input (passwords, `read -s`)
# is recorded too (codex cycle 2 finding-5).
#
# Run script as a CHILD (not `exec`) so the wrapper survives to fire
# the EXIT trap and kill tcpdump (codex cycle 1 finding-7). Forward
# script's exit status via $? so SSH sees the right return code.
SCRIPT_ARGS=( -q -f --return --log-io "$PTY_TS" --log-timing "$PTY_TIMING" )
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  script "${SCRIPT_ARGS[@]}" --command "$SSH_ORIGINAL_COMMAND"
else
  script "${SCRIPT_ARGS[@]}" --command "/bin/bash --login"
fi
exit $?
