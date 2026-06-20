#!/bin/bash
# APTL Kali Capture Sidecar entrypoint (ADR-041 / issue #305).
#
# Starts auditd (with the APTL ruleset mounted from the kali image),
# process accounting, and the writer daemon.  All capture subsystem
# boot outcomes are written to /run/aptl-kali-capture-ready.
set -e

auditd_status=degraded
procacct_status=degraded

mkdir -p /var/log/aptl/captures/_audit /var/log/aptl/captures/_proc-acct
chmod 0700 /var/log/aptl/captures/_audit /var/log/aptl/captures/_proc-acct

# Start auditd with APTL ruleset
if command -v auditctl >/dev/null 2>&1 && [ -f /etc/audit/rules.d/aptl.rules ]; then
    if [ -f /etc/audit/auditd.conf ]; then
        sed -i 's|^log_file *=.*|log_file = /var/log/aptl/captures/_audit/audit.log|' \
            /etc/audit/auditd.conf || true
    fi
    # touch (create-if-missing) — NOT truncate — preserves prior events on restart
    touch /var/log/aptl/captures/_audit/audit.log
    chmod 0600 /var/log/aptl/captures/_audit/audit.log
    if auditctl -R /etc/audit/rules.d/aptl.rules >/dev/null 2>&1 && \
       auditd >/dev/null 2>&1; then
        auditd_status=ok
        echo "[kali-capture] auditd started with APTL rules"
    else
        echo "[kali-capture] auditd start failed (missing AUDIT_CONTROL?); continuing"
    fi
else
    echo "[kali-capture] auditctl or aptl.rules missing; auditd skipped"
fi

# Start process accounting
if command -v accton >/dev/null 2>&1; then
    touch /var/log/aptl/captures/_proc-acct/pacct
    chown root:root /var/log/aptl/captures/_proc-acct/pacct
    chmod 0600 /var/log/aptl/captures/_proc-acct/pacct
    if accton /var/log/aptl/captures/_proc-acct/pacct; then
        procacct_status=ok
        echo "[kali-capture] process accounting active"
    else
        echo "[kali-capture] accton failed (missing SYS_PACCT?); continuing"
    fi
fi

# Write sidecar readiness marker
mkdir -p /run
{
    echo "ready_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "auditd=${auditd_status}"
    echo "procacct=${procacct_status}"
} > /run/aptl-kali-capture-ready

echo "=== APTL Kali Capture Sidecar Ready ==="
echo "auditd=${auditd_status} procacct=${procacct_status}"

exec python3 /usr/local/bin/writer.py
