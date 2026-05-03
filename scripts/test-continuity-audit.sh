#!/usr/bin/env bash
# End-to-end smoke validation for the orchestrator-side purple-team
# continuity carve-out (issue #252, ADR-024).
#
# Manual-runnable counterpart to tests/test_continuity.py's LIVE_LAB
# suite. Demonstrates that `aptl lab continuity-audit`:
#   1. Reverts a blanket kali source-IP DROP rule.
#   2. Preserves a port-qualified kali rule (granular tradecraft).
#   3. Is idempotent on a clean tree.
#
# Procedure:
#   - Inject `iptables -I INPUT -s <kali_ip> -j DROP` on a target.
#   - Run `aptl lab continuity-audit`.
#   - Verify the rule is gone and `iptables -S INPUT` no longer
#     contains the kali source.
#   - Inject a port-qualified equivalent.
#   - Re-run the audit; verify the rule is *still* present.
#   - Cleanup: drop any test rule that survived.
#
# Idempotent, safe to re-run. Exits 0 on success.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-/home/atomik/src/aptl}"
# ``aptl-webapp`` is in IN_PROCESS_TARGETS (#248): NET_ADMIN + in-process
# agent. ``aptl-victim``/``aptl-workstation`` ship without NET_ADMIN and
# are not in ``default_targets()`` — this script needs a target the
# audit will actually inspect.
TARGET="${TARGET:-aptl-webapp}"
KALI_SRC_IP="${KALI_SRC_IP:-172.20.4.30}"

log()  { echo "[test-continuity-audit] $*"; }
fail() { log "FAIL: $*"; exit 1; }

# --- preconditions ----------------------------------------------------------
if ! command -v aptl >/dev/null 2>&1; then
    fail "aptl CLI not on PATH; install with 'pip install -e .' under $REPO_ROOT"
fi
if ! docker exec "$TARGET" true >/dev/null 2>&1; then
    fail "$TARGET is not running; start the lab first (aptl lab start)"
fi

# --- cleanup helper (run on entry + exit) ----------------------------------
clear_kali_rules() {
    # Best-effort delete of any leftover kali-drop rule. iptables -D
    # returns 1 when no matching rule exists; we expect that to be the
    # terminating condition of the loop.
    local i
    for i in $(seq 1 10); do
        if ! docker exec "$TARGET" iptables -D INPUT -s "$KALI_SRC_IP" -j DROP 2>/dev/null; then
            break
        fi
    done
    for i in $(seq 1 10); do
        if ! docker exec "$TARGET" iptables -D INPUT -s "$KALI_SRC_IP" -p tcp -m tcp --dport 22 -j DROP 2>/dev/null; then
            break
        fi
    done
}
trap clear_kali_rules EXIT

log "Pre-clean any leftover kali-drop rules on $TARGET"
clear_kali_rules

# --- 1) blanket drop is reverted -------------------------------------------
log "Step 1: inject blanket kali DROP and run audit"
docker exec "$TARGET" iptables -I INPUT -s "$KALI_SRC_IP" -j DROP

(cd "$REPO_ROOT" && aptl lab continuity-audit) || \
    fail "continuity-audit exited non-zero with a blanket rule present"

if docker exec "$TARGET" iptables -S INPUT | grep -E "^-A INPUT -s ${KALI_SRC_IP}(/32)? -j (DROP|REJECT)$" >/dev/null; then
    fail "blanket rule was NOT reverted"
fi
log "  ok: blanket rule was reverted"

# --- 2) port-qualified rule is preserved ------------------------------------
log "Step 2: inject port-qualified kali drop and run audit"
docker exec "$TARGET" iptables -I INPUT -s "$KALI_SRC_IP" -p tcp -m tcp --dport 22 -j DROP

(cd "$REPO_ROOT" && aptl lab continuity-audit) || \
    fail "continuity-audit exited non-zero with only granular rules present"

if ! docker exec "$TARGET" iptables -S INPUT | grep -E "${KALI_SRC_IP}.*--dport 22" >/dev/null; then
    fail "granular port-qualified rule was incorrectly reverted"
fi
log "  ok: granular rule was preserved"

# --- 3) idempotent on clean tree -------------------------------------------
log "Step 3: clean tree, audit again, expect no findings"
clear_kali_rules

if ! (cd "$REPO_ROOT" && aptl lab continuity-audit | grep -E "no blanket kali" >/dev/null); then
    fail "audit on clean tree did not report 'no blanket kali source-IP rules'"
fi
log "  ok: idempotent on clean tree"

log "PASS: continuity-audit behaves correctly across all three cases"
