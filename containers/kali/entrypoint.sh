#!/bin/bash
# APTL Kali entrypoint (OBS-003 / ADR-033 / ADR-041 revision).
#
# ADR-041: auditd, process accounting, and all capture writes have moved
# to the aptl-kali-capture sidecar.  This entrypoint no longer starts
# those subsystems.  The kali_captures volume is NOT mounted in this
# container at all (not even read-only), so the kali user (passwordless
# sudo) cannot read, list, delete, or modify any session's evidence.
#
# Remaining responsibilities:
#   - SSH key setup
#   - sshd, spawned with CAP_AUDIT_CONTROL dropped via capsh
#   - OBS-003 ForceCommand wrapper presence check
#   - Boot-readiness marker (sshd + wrapper status only)
set -e

sshd_status=degraded
wrapper_status=degraded

# Set up SSH keys from host.
if [ -f "/host-ssh-keys/authorized_keys" ]; then
    mkdir -p /home/kali/.ssh
    cp /host-ssh-keys/authorized_keys /home/kali/.ssh/authorized_keys
    chown -R kali:kali /home/kali/.ssh
    chmod 700 /home/kali/.ssh
    chmod 600 /home/kali/.ssh/authorized_keys
    echo "SSH keys configured for kali user"
fi

# SEC #417: copy pivot private key into kali's home with correct ownership.
if [ -f "/host-ssh-keys/kali_pivot_key" ]; then
    mkdir -p /home/kali/.ssh
    cp /host-ssh-keys/kali_pivot_key /home/kali/.ssh/kali_pivot_key
    chown -R kali:kali /home/kali/.ssh
    chmod 700 /home/kali/.ssh
    chmod 600 /home/kali/.ssh/kali_pivot_key
    echo "Kali pivot key configured for kali user"
fi

# ADR-041: no captures volume is mounted here, so there is nothing to
# create or chown under /var/log/aptl — the sidecar owns the sink.

# Final ownership repair on home dir (idempotent).
chown -R kali:kali /home/kali/

# Spawn sshd with CAP_AUDIT_CONTROL DROPPED (codex finding-12).
# The kali user with passwordless sudo can otherwise run
# `sudo auditctl -D` and erase the audit trail mid-scenario.
mkdir -p /run/sshd
if command -v capsh >/dev/null 2>&1; then
    if capsh --drop=cap_audit_control -- -c '/usr/sbin/sshd'; then
        sshd_status=ok
    else
        echo "[entrypoint] capsh-wrapped sshd failed; falling back" >&2
        if /usr/sbin/sshd; then sshd_status=ok; fi
    fi
else
    echo "[entrypoint] capsh missing; sshd running with full caps" >&2
    if /usr/sbin/sshd; then sshd_status=ok; fi
fi
if [ "$sshd_status" = "ok" ]; then
    echo "SSH daemon started"
else
    echo "[entrypoint] WARNING: sshd failed to start" >&2
fi

# OBS-003 ForceCommand wrapper presence check.
if [ -x /usr/local/bin/aptl-wrap-shell.sh ]; then
    wrapper_status=ok
else
    echo "[entrypoint] WARNING: OBS-003 ForceCommand wrapper missing/not executable" >&2
fi

# Boot-readiness marker.  sshd and wrapper are the only managed
# subsystems in this container; capture subsystems are in the sidecar.
mkdir -p /run
{
    echo "ready_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "sshd=${sshd_status}"
    echo "wrapper=${wrapper_status}"
} > /run/aptl-kali-ready

echo "=== APTL Kali Red Team Container Ready ==="
echo "SSH: ssh kali@<container_ip>"
echo "Boot readiness: sshd=${sshd_status} wrapper=${wrapper_status}"
echo "Capture subsystems: managed by aptl-kali-capture sidecar (ADR-041)"

exec sleep infinity
