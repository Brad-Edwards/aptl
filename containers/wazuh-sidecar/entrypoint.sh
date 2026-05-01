#!/bin/bash
# APTL Wazuh sidecar entrypoint: register with the manager, ship configured
# log paths, and stay attached to the agent process so docker can manage
# lifecycle and surface logs.
set -euo pipefail

: "${WAZUH_MANAGER:?WAZUH_MANAGER is required}"
: "${AGENT_NAME:?AGENT_NAME is required}"
: "${LOG_PATHS:?LOG_PATHS is required (comma-separated, paths under /logs)}"

# Optional knobs
LOG_FORMAT="${LOG_FORMAT:-syslog}"     # syslog | json | multi-line | command | full_command
WAIT_TIMEOUT="${WAIT_TIMEOUT:-180}"    # seconds to wait for manager to be reachable

log() { echo "[wazuh-sidecar:${AGENT_NAME}] $*"; }

log "starting; manager=${WAZUH_MANAGER}, paths=${LOG_PATHS}, format=${LOG_FORMAT}"

# 1. Wait for the manager registration port (1515) to accept connections.
log "waiting for ${WAZUH_MANAGER}:1515 (auth)..."
deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
while ! nc -z -w 2 "${WAZUH_MANAGER}" 1515 2>/dev/null; do
    if [ "$(date +%s)" -ge "${deadline}" ]; then
        log "manager auth port did not open within ${WAIT_TIMEOUT}s; continuing anyway"
        break
    fi
    sleep 3
done

# 2. Build the localfile blocks for each requested path.
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

# 3. Render ossec.conf from the template.
TEMPLATE=/opt/wazuh-sidecar/ossec.conf.template
TARGET=/var/ossec/etc/ossec.conf
LF_FILE="$(mktemp)"
printf '%s\n' "$LF" > "$LF_FILE"
# Two-step substitution: scalar tokens via sed, then localfile block via awk
# (sed's multi-line replace is fragile; awk reading from a file is robust).
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

# 4. Register with the manager (agent-auth). Idempotent - re-running with the
#    same name just refreshes the key.
log "registering as '${AGENT_NAME}' with ${WAZUH_MANAGER}..."
if ! /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -A "${AGENT_NAME}" 2>&1 | tee /tmp/agent-auth.log; then
    log "agent-auth returned non-zero; will let agentd retry"
fi

# 5. Make sure no stale pids prevent startup.
rm -f /var/ossec/var/run/*.pid /var/ossec/queue/sockets/* 2>/dev/null || true

# 6. Start the agent processes.
log "starting wazuh-agent..."
/var/ossec/bin/wazuh-control start

# 7. Stay attached so docker can stream agent log + manage lifecycle.
log "ready; tailing /var/ossec/logs/ossec.log"
exec tail -F /var/ossec/logs/ossec.log
