#!/bin/bash
# Shared Wazuh agent bootstrap (issue #248).
#
# Used by:
#   - containers/wazuh-sidecar/Dockerfile  (sidecar pattern; runs as ENTRYPOINT)
#   - containers/{webapp,fileshare,ad,dns}/  (in-process pattern;
#     runs as a supervisord program alongside the primary service)
#
# In both cases the script:
#   1. waits for the manager's auth port (1515) to accept connections,
#   2. renders /var/ossec/etc/ossec.conf from the template using the
#      WAZUH_MANAGER, AGENT_NAME, LOG_PATHS, and LOG_FORMAT env vars,
#   3. registers with the manager via agent-auth (idempotent — `-F 1`
#      replaces a same-named agent record left over from a previous
#      sidecar deployment when the in-process container takes over),
#   4. starts wazuh-control,
#   5. exec tails ossec.log so the calling supervisor (docker for the
#      sidecar; supervisord for the in-process targets) can manage
#      lifecycle and surface logs.
set -euo pipefail

: "${WAZUH_MANAGER:?WAZUH_MANAGER is required}"
: "${AGENT_NAME:?AGENT_NAME is required}"
: "${LOG_PATHS:?LOG_PATHS is required (comma-separated paths)}"

LOG_FORMAT="${LOG_FORMAT:-syslog}"     # syslog | json | multi-line | command | full_command
WAIT_TIMEOUT="${WAIT_TIMEOUT:-180}"    # seconds to wait for manager
TEMPLATE="${WAZUH_AGENT_TEMPLATE:-/opt/aptl/wazuh/ossec.conf.template}"

log() { echo "[wazuh-agent:${AGENT_NAME}] $*"; }

log "starting; manager=${WAZUH_MANAGER}, paths=${LOG_PATHS}, format=${LOG_FORMAT}"

# 1. Wait for manager registration port.
log "waiting for ${WAZUH_MANAGER}:1515 (auth)..."
deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
while ! nc -z -w 2 "${WAZUH_MANAGER}" 1515 2>/dev/null; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
        log "manager auth port did not open within ${WAIT_TIMEOUT}s; continuing anyway"
        break
    fi
    sleep 3
done

# 2. Build localfile blocks for every requested path.
LF=""
IFS=',' read -ra PATHS <<< "${LOG_PATHS}"
for p in "${PATHS[@]}"; do
    p="$(echo "$p" | xargs)"
    [ -z "$p" ] && continue
    LF="${LF}
  <localfile>
    <log_format>${LOG_FORMAT}</log_format>
    <location>${p}</location>
  </localfile>"
done

# 3. Render ossec.conf from template.
TARGET=/var/ossec/etc/ossec.conf
LF_FILE="$(mktemp)"
printf '%s\n' "$LF" > "$LF_FILE"
sed -e "s|__WAZUH_MANAGER__|${WAZUH_MANAGER}|g" \
    -e "s|__AGENT_NAME__|${AGENT_NAME}|g" \
    "${TEMPLATE}" \
  | awk -v LFFILE="$LF_FILE" '
        /__LOCALFILE_BLOCKS__/ {
            while ((getline line < LFFILE) > 0) print line
            close(LFFILE)
            next
        }
        { print }
    ' > "${TARGET}"
rm -f "$LF_FILE"
chown root:wazuh "${TARGET}" 2>/dev/null || true
chmod 640 "${TARGET}" 2>/dev/null || true

# 4. Register with the manager. Wazuh 4.12's agent-auth has no `-F`
#    flag; the manager auto-replaces a same-named agent record, so the
#    in-process registration takes over from any prior sidecar
#    registration. If client.keys is already populated from an earlier
#    successful registration, agent-auth is a no-op refresh; if it is
#    empty (fresh container) and registration fails, the agent has no
#    identity and would silently fail to connect — fail fast in that
#    case so supervisord/`startretries` retries the bootstrap.
log "registering as '${AGENT_NAME}' with ${WAZUH_MANAGER}..."
if ! /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -A "${AGENT_NAME}" 2>&1 | tee /tmp/agent-auth.log; then
    log "agent-auth returned non-zero"
    if ! [ -s /var/ossec/etc/client.keys ]; then
        log "ERROR: client.keys is empty and agent-auth failed; cannot start agent. Exiting so the supervisor can retry."
        exit 1
    fi
    log "client.keys is populated from a previous registration; continuing with the existing identity"
fi

# 5. Make sure no stale pids prevent startup.
rm -f /var/ossec/var/run/*.pid /var/ossec/queue/sockets/* 2>/dev/null || true

# 6. Start the agent processes (wazuh-control launches the daemons in
#    the background; we then watch the main agentd process so the
#    supervisor sees the actual agent, not just a `tail`).
log "starting wazuh-agent..."
/var/ossec/bin/wazuh-control start

# Find the wazuh-agentd PID. wazuh-control runs detached, so we have
# to discover it after start.
deadline=$(( $(date +%s) + 30 ))
AGENTD_PID=""
while [ "$(date +%s)" -lt "${deadline}" ]; do
    AGENTD_PID="$(pgrep -x wazuh-agentd 2>/dev/null | head -1 || true)"
    if [ -n "${AGENTD_PID}" ]; then
        break
    fi
    sleep 1
done
if [ -z "${AGENTD_PID}" ]; then
    log "ERROR: wazuh-agentd did not start within 30s; exiting so the supervisor can retry"
    exit 1
fi

log "ready; agentd pid=${AGENTD_PID}; surfacing /var/ossec/logs/ossec.log"

# 7. Stream the agent log in the background, then `wait` on agentd
#    itself. If agentd dies, this script exits with its exit code so
#    the supervising process (docker for the sidecar; supervisord for
#    in-process targets) restarts it. tail-F alone would mask agent
#    crashes — supervisord would see a healthy `tail` and never
#    restart the actual agent.
tail -F /var/ossec/logs/ossec.log &
TAIL_PID=$!
trap 'kill -TERM "${TAIL_PID}" 2>/dev/null || true' EXIT

# `wait` on a non-child PID is not portable; use a polling loop.
while kill -0 "${AGENTD_PID}" 2>/dev/null; do
    sleep 5
done

log "wazuh-agentd (pid ${AGENTD_PID}) exited; this script will exit so the supervisor restarts it"
exit 1
