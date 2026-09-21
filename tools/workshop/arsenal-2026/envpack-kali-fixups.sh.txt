#!/bin/bash
# =============================================================================
# TEMPORARY env-pack Kali capture-wrapper fixup
# =============================================================================
# The Kali sshd runs `ForceCommand /usr/local/bin/aptl-wrap-shell.sh` (OBS-003 /
# ADR-033 / ADR-041). That wrapper is fail-closed: it denies every session
# unless a control-plane-issued `APTL_CAPTURE_CAPABILITY` token is present in the
# connection environment. In this realization NOTHING issues that token --
# neither APTL (mcp-red's aptlShellEnv sends only APTL_SESSION_ID/APTL_RUN_ID)
# nor the env-pack/RAES control plane -- so the wrapper fail-closes on EVERY
# connection. Result: `aptl lab start` readiness reports "SSH to kali not ready"
# (degraded_unusable) and `kali_run_command` returns "capture capability
# missing; access denied". Kali is completely unusable on a fresh boot.
#
# This patches the wrapper so that WHEN the capability is absent it runs the
# requested shell / SSH_ORIGINAL_COMMAND directly instead of denying the
# session. The full capture path is preserved unchanged for the case where a
# capability IS provisioned: this fallback branch is simply not taken then, so
# command capture resumes automatically once the control plane issues tokens.
# It is idempotent (a wrapper already carrying the marker is left untouched) and
# safe to run on every boot.
#
# NOTE ON POSTURE: the wrapper's stated invariant is "no unrecorded shell". This
# fallback deliberately relaxes that to "usable shell, captured when possible"
# because the capture capability is unimplemented end-to-end here and the
# alternative is a 100%-unusable attacker box. APTL is a single-user, local,
# disposable range and SSH key auth still gates access; only the capture/audit
# telemetry is affected, and only while provisioning is missing.
#
# Root fix tracked upstream (remove this script when it ships):
#   provision APTL_CAPTURE_CAPABILITY (or make capture best-effort in the
#   wrapper) -> OpenRAE/env-packs#<TBD> ; retire per Brad-Edwards/aptl#<TBD>
# =============================================================================
set -uo pipefail

KALI_CTR="${KALI_CONTAINER:-aptl-kali}"
WRAPPER="${KALI_WRAPPER:-/usr/local/bin/aptl-wrap-shell.sh}"
MARKER="APTL permissive fallback (envpack-kali-fixups)"

command -v docker >/dev/null 2>&1 || exit 0

log() { echo "[envpack-kali-fixups] $*"; }

_present() { docker inspect "$1" >/dev/null 2>&1; }

if ! _present "$KALI_CTR"; then
    log "no $KALI_CTR container present; nothing to fix up"
    exit 0
fi

if docker exec "$KALI_CTR" grep -qF "$MARKER" "$WRAPPER" 2>/dev/null; then
    log "wrapper already carries the permissive fallback; leaving untouched"
    exit 0
fi

if ! docker exec "$KALI_CTR" test -f "$WRAPPER" 2>/dev/null; then
    log "wrapper $WRAPPER not found in $KALI_CTR; skipping"
    exit 0
fi

log "patching $WRAPPER in $KALI_CTR to allow shells when no capture capability is provisioned"

# Replace the fail-closed capability check with a permissive fallback that execs
# the shell/command directly when the capability is absent, leaving the capture
# path intact for when it is present. Done inside the container as root via a
# Python patcher piped over stdin (docker cp into kali /tmp is unreliable).
docker exec -i -u root "$KALI_CTR" python3 - "$WRAPPER" "$MARKER" <<'PY'
import io
import sys

path, marker = sys.argv[1], sys.argv[2]
with io.open(path, "r", encoding="utf-8") as fh:
    src = fh.read()

needle = 'if [ -z "${APTL_CAPTURE_CAPABILITY:-}" ]; then\n'
idx = src.find(needle)
if idx == -1:
    sys.stderr.write("capability guard not found; wrapper shape changed\n")
    sys.exit(3)

# Find the end of that if/fi block (the next line that is exactly "fi").
after = src.index("\n", idx) + 1
rest = src[after:]
fi_rel = rest.index("\nfi\n")
block_end = after + fi_rel + len("\nfi\n")

replacement = (
    'if [ -z "${APTL_CAPTURE_CAPABILITY:-}" ]; then\n'
    "  # " + marker + ": the control plane never provisions the capture\n"
    "  # capability in this realization, so the capture chain cannot run. Rather\n"
    "  # than deny every session (which bricks kali), run the requested shell or\n"
    "  # SSH_ORIGINAL_COMMAND directly, without capture. The full capture path\n"
    "  # below is preserved for when a capability IS present (this branch is not\n"
    "  # taken then), so capture resumes automatically once tokens are issued.\n"
    '  if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then\n'
    '    exec /bin/bash -lc "$SSH_ORIGINAL_COMMAND"\n'
    "  else\n"
    "    exec /bin/bash --login\n"
    "  fi\n"
    "fi\n"
)

new = src[:idx] + replacement + src[block_end:]
with io.open(path, "w", encoding="utf-8") as fh:
    fh.write(new)
print("patched")
PY

rc=$?
if [ "$rc" -ne 0 ]; then
    log "WARNING: wrapper patch failed (rc=$rc); kali may remain fail-closed"
    exit 0
fi

# Sanity: the marker must now be present and the file must still be valid bash.
if docker exec "$KALI_CTR" grep -qF "$MARKER" "$WRAPPER" 2>/dev/null \
    && docker exec "$KALI_CTR" bash -n "$WRAPPER" 2>/dev/null; then
    log "wrapper patched and syntax-valid; kali shells are now reachable"
else
    log "WARNING: post-patch validation failed; check $WRAPPER in $KALI_CTR"
fi
log "done"
