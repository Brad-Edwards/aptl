#!/bin/bash
# APTL Kali entrypoint (OBS-003 / ADR-033 revision, hardened against
# codex pre-push cycle 1 findings).
#
# Brings up the Kali container with the OBS-003 capture surface:
#   - sshd, spawned with CAP_AUDIT_CONTROL dropped via capsh so the
#     kali user (passwordless sudo) cannot run `auditctl -D` to
#     disable audit mid-scenario (codex finding-12).
#   - auditd loaded with the APTL ruleset BEFORE sshd, so audit is
#     active by the time the agent connects.
#   - process accounting (accton) writing into the kali_captures
#     named volume so events survive container restart and harvest
#     out alongside per-session pcaps and PTY recordings (codex
#     finding-5).
#
# Wazuh agent installation and rsyslog forwarding to the SIEM,
# present in prior revisions, were removed under the
# non-contamination principle: red activity must not bleed into the
# blue defensive stack's awareness. See ADR-033.
set -e

# Set up SSH keys from host.
if [ -f "/host-ssh-keys/authorized_keys" ]; then
    mkdir -p /home/kali/.ssh
    cp /host-ssh-keys/authorized_keys /home/kali/.ssh/authorized_keys
    chown -R kali:kali /home/kali/.ssh
    chmod 700 /home/kali/.ssh
    chmod 600 /home/kali/.ssh/authorized_keys
    echo "SSH keys configured for kali user"
fi

# OBS-003: prepare the captures volume mount. /var/log/aptl/captures
# is a docker NAMED VOLUME (see docker-compose.yml). We chown only
# the captures root + its container-wide audit/proc-acct subdirs so
# the kali user can write per-session subdirs — NOT recursive into
# any prior run's MCP-side records (codex finding-4: the prior
# `chown -R /var/log/aptl` would have mutated host-side data when
# bound to a host filesystem; the named volume approach + scoped
# chown closes both issues).
mkdir -p /var/log/aptl/captures \
         /var/log/aptl/captures/_audit \
         /var/log/aptl/captures/_proc-acct
chown root:root /var/log/aptl /var/log/aptl/captures \
                /var/log/aptl/captures/_audit \
                /var/log/aptl/captures/_proc-acct
chmod 0755 /var/log/aptl
# 0701 on the captures root lets the kali user `cd` into per-run
# subdirs (created by the wrapper as kali) without granting `ls`
# access to siblings — protects against cross-session snooping
# inside the same lab run.
chmod 0701 /var/log/aptl/captures
chmod 0700 /var/log/aptl/captures/_audit /var/log/aptl/captures/_proc-acct
# Give kali write access to the captures root so the per-session
# wrapper can mkdir its run_id/session_id subdirs.
setfacl -m u:kali:rwx /var/log/aptl/captures 2>/dev/null \
  || chmod 0707 /var/log/aptl/captures  # fallback if setfacl missing

# OBS-003: process accounting → captures volume. pacct accumulates
# every process that exits; restart-survival comes from the volume.
# Use `touch` (create-if-missing) — NOT `: >` (truncate) — so a
# container restart mid-run doesn't erase the persisted accounting
# evidence (codex cycle 2 finding-3).
if command -v accton >/dev/null 2>&1; then
    touch /var/log/aptl/captures/_proc-acct/pacct
    chown root:root /var/log/aptl/captures/_proc-acct/pacct
    chmod 0600 /var/log/aptl/captures/_proc-acct/pacct
    accton /var/log/aptl/captures/_proc-acct/pacct \
      || echo "[entrypoint] accton failed (best-effort)"
    echo "Process accounting active"
fi

# OBS-003: auditd. Load rules with full CAP_AUDIT_CONTROL (we have it
# at entrypoint), then start the daemon. Subsequent sshd spawn drops
# the capability so the kali user can't modify the loaded ruleset.
audit_loaded=0
if command -v auditctl >/dev/null 2>&1 && [ -f /etc/audit/rules.d/aptl.rules ]; then
    if auditctl -R /etc/audit/rules.d/aptl.rules >/dev/null 2>&1; then
        echo "auditd rules loaded"
        audit_loaded=1
    else
        echo "[entrypoint] auditctl -R failed; auditd disabled"
    fi
fi
if [ "$audit_loaded" = "1" ] && command -v auditd >/dev/null 2>&1; then
    # Redirect auditd's log into the captures named volume so the
    # events survive container restart and are pulled out by the
    # MCP-side harvest alongside per-session pcaps/PTYs (codex
    # finding-5). Without this, /var/log/audit lives in the overlay
    # fs and is lost on `docker compose down -v`.
    if [ -f /etc/audit/auditd.conf ]; then
        sed -i 's|^log_file *=.*|log_file = /var/log/aptl/captures/_audit/audit.log|' \
            /etc/audit/auditd.conf || true
    fi
    # `touch` (create-if-missing), NOT truncate — preserves prior
    # audit events on container restart (codex cycle 2 finding-3).
    touch /var/log/aptl/captures/_audit/audit.log
    chmod 0600 /var/log/aptl/captures/_audit/audit.log
    auditd >/dev/null 2>&1 \
      || echo "[entrypoint] auditd start failed (missing CAP_AUDIT_*?)"
fi

# Final ownership repair on home dir (cheap, idempotent — NOT the
# captures volume; that one is scoped above).
chown -R kali:kali /home/kali/

# Spawn sshd with CAP_AUDIT_CONTROL DROPPED (codex finding-12). The
# kali user with passwordless sudo can otherwise run `sudo
# auditctl -D` and erase the audit trail mid-scenario. capsh runs
# the program in a child process with the bounding set masked, so
# sudo (which queries the bounding set, not just the file caps)
# inherits the restriction transitively.
mkdir -p /run/sshd
if command -v capsh >/dev/null 2>&1; then
    # `--drop=cap_audit_control` removes only the dangerous capability;
    # sshd retains everything else it needs. If capsh fails (unlikely
    # — it's in libcap2-bin which is in the kali base), fall back to
    # unwrapped sshd so the lab still works, but log loudly.
    capsh --drop=cap_audit_control -- -c '/usr/sbin/sshd' \
      || { echo "[entrypoint] capsh-wrapped sshd failed; falling back" >&2 ; \
           /usr/sbin/sshd ; }
else
    echo "[entrypoint] capsh missing; sshd running with full caps (auditd disable risk)" >&2
    /usr/sbin/sshd
fi
echo "SSH daemon started"

echo "=== APTL Kali Red Team Container Ready ==="
echo "SSH: ssh kali@<container_ip>"
echo "Working directory: /home/kali/operations"
echo "Per-session captures: /var/log/aptl/captures/<run_id>/<session_id>/ (in named volume)"
echo "Harvest target on host: .aptl/runs/<run_id>/kali-side/<session_id>/"

# Keep container alive (PID 1 keepalive).
exec sleep infinity
