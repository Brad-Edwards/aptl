#!/bin/bash
# APTL Kali container healthcheck (ADR-033 §2 / issue #293).
#
# Verifies the *usable surface* of the container, not merely that
# port 22 is open. A boot that died after sshd started but before the
# entrypoint finished bringing up the OBS-003 capture surface
# previously still reported healthy — this check fails it.
#
# Hard requirements (exit 1 -> container marked unhealthy):
#   - sshd is listening on :22
#   - the OBS-003 ForceCommand wrapper is installed and executable
#   - the entrypoint wrote its boot-readiness marker (its presence
#     proves the entrypoint ran to completion: `set -e` aborts the
#     entrypoint before the marker on any hard failure)
#
# Capture-daemon degradation (auditd / process accounting) is NOT a
# hard failure here. It is recorded per-subsystem in the readiness
# marker and the entrypoint logs as the "clear degraded-startup
# signal" ADR-033 §2 calls for, and echoed below so it shows in
# `docker inspect`'s health log. auditd legitimately cannot bind the
# kernel audit netlink socket on hosts already running their own
# auditd, so failing the container on it would produce false alarms.
set -u

READY_MARKER="/run/aptl-kali-ready"
WRAPPER="/usr/local/bin/aptl-wrap-shell.sh"

fail() {
    echo "[healthcheck] UNHEALTHY: $1" >&2
    exit 1
}

# 1. sshd listening on :22. The trailing-boundary match avoids a
#    false positive on ports like :2200.
if ! ss -tln 2>/dev/null | grep -qE ':22([[:space:]]|$)'; then
    fail "sshd is not listening on :22"
fi

# 2. OBS-003 ForceCommand wrapper present and executable.
if [ ! -x "$WRAPPER" ]; then
    fail "ForceCommand wrapper $WRAPPER missing or not executable"
fi

# 3. Entrypoint completed boot and wrote the readiness marker.
if [ ! -f "$READY_MARKER" ]; then
    fail "boot-readiness marker $READY_MARKER absent — entrypoint did not complete boot"
fi

# Surface (but do not fail on) degraded capture subsystems.
degraded="$(grep -E '=degraded$' "$READY_MARKER" 2>/dev/null | cut -d= -f1 | tr '\n' ' ')"
degraded="${degraded%% }"
if [ -n "$degraded" ]; then
    echo "[healthcheck] healthy (degraded capture subsystems: ${degraded})"
else
    echo "[healthcheck] healthy"
fi
exit 0
