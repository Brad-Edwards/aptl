#!/usr/bin/env bash
# End-to-end validation that Wazuh active-response can drop kali->target
# packets when the agent runs in-process on the target (issue #248 AC#3).
#
# This script is the manual-runnable counterpart to
# tests/test_in_process_agents.py. It demonstrates the full prevention
# pipeline that ADR-019 + ADR-020 established:
#   eve.json / agent log -> Wazuh manager rule -> AR command ->
#   in-process agent -> iptables -I in target namespace -> drop.
#
# Procedure (against the webapp target — the most-attacked container):
#   1. Sanity check: lab is up, kali can reach webapp.
#   2. Append a temporary <active-response> block to the manager that
#      links a benign rule (HTTP 401 on webapp) to firewall-drop, with a
#      120s timeout so any leftover state auto-expires after the test.
#      Also append a temporary local rule that decodes a marker URL into
#      an alert at level >= 5 so the AR block actually fires.
#   3. Restart the manager so the new config is live.
#   4. From kali, hit the marker URL to trigger the rule.
#   5. Wait for AR to install the iptables drop in webapp.
#   6. Probe again from kali — must time out / fail.
#   7. Clean up the temporary rule + AR block, restart the manager, and
#      verify connectivity is restored.
#
# Idempotent (sentinel-tagged), safe to re-run after partial failure.
# Exit 0 = pass; non-zero = fail with a clear message.

set -euo pipefail

# --- config -----------------------------------------------------------------
REPO_ROOT="${REPO_ROOT:-/home/atomik/src/aptl}"
MANAGER="${MANAGER:-aptl-wazuh-manager}"
TARGET="${TARGET:-aptl-webapp}"
KALI="${KALI:-aptl-kali}"
WEBAPP_HOST="${WEBAPP_HOST:-172.20.1.20}"
WEBAPP_PORT="${WEBAPP_PORT:-8080}"
KALI_SRC_IP="${KALI_SRC_IP:-172.20.4.30}"
PROBE_PATH="${PROBE_PATH:-/aptl-ar-test-marker-$(date -u +%s)}"
SENTINEL="<!-- APTL-AR-TEST (managed by scripts/test-wazuh-ar-drop.sh) -->"
TMP_RULE_FILE="/var/ossec/etc/rules/zzz_aptl_ar_test.xml"
WAIT_AR_SEC="${WAIT_AR_SEC:-30}"
WAIT_MGR_SEC="${WAIT_MGR_SEC:-30}"
# A signature ID that doesn't collide with the lab's existing rules
# (existing custom rules use 1xx-3xx ranges per kali_redteam_rules.xml,
# webapp_rules.xml, etc.; 1999500 is well above that block).
TMP_SID="${TMP_SID:-1999500}"

# --- helpers ----------------------------------------------------------------
log()  { echo "[test-wazuh-ar-drop] $*"; }
fail() { log "FAIL: $*"; exit 1; }

cleanup_rule() {
    log "removing temporary AR rule from ${MANAGER}"
    docker exec "${MANAGER}" sh -c "rm -f ${TMP_RULE_FILE}" 2>/dev/null || true

    # Remove any AR block we added to ossec.conf (sentinel-tagged for
    # surgical removal). The conf file is templated at startup so a
    # crude grep-and-rebuild is safer than in-place sed.
    docker exec "${MANAGER}" sh -c "
        if grep -Fq '${SENTINEL}' /var/ossec/etc/ossec.conf 2>/dev/null; then
            awk '
                /${SENTINEL}/   { skip = !skip; next }
                !skip
            ' /var/ossec/etc/ossec.conf > /tmp/ossec.conf.new
            mv /tmp/ossec.conf.new /var/ossec/etc/ossec.conf
            chown root:wazuh /var/ossec/etc/ossec.conf 2>/dev/null || true
            chmod 640 /var/ossec/etc/ossec.conf 2>/dev/null || true
        fi
    " 2>/dev/null || true
}

restart_manager_and_wait() {
    log "restarting ${MANAGER}"
    docker restart "${MANAGER}" >/dev/null
    log "waiting ${WAIT_MGR_SEC}s for manager to become healthy"
    sleep "${WAIT_MGR_SEC}"
}

restart_target_and_wait() {
    # The target's in-process agent reconnects automatically on manager
    # restart; the target itself does not need to be restarted. This
    # function exists for the cleanup phase if the iptables state needs
    # to be flushed faster than the AR timeout.
    log "flushing iptables in ${TARGET} as a belt-and-braces cleanup"
    docker exec "${TARGET}" sh -c '
        iptables -F INPUT 2>/dev/null || true
    ' 2>/dev/null || true
}

curl_from_kali() {
    docker exec "${KALI}" curl \
        -m 5 --connect-timeout 3 \
        -s -o /dev/null \
        -w "%{http_code}" \
        "http://${WEBAPP_HOST}:${WEBAPP_PORT}${1}" 2>/dev/null \
        || echo "TIMEOUT"
}

# --- preflight --------------------------------------------------------------
trap cleanup_rule EXIT

for c in "${MANAGER}" "${TARGET}" "${KALI}"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        fail "${c} not running. Run: aptl lab start"
    fi
done

cleanup_rule  # in case a prior run left state behind

# --- step 1: sanity (kali can reach webapp before AR fires) ----------------
log "sanity: kali -> webapp baseline"
baseline_code=$(curl_from_kali "/")
if [ "${baseline_code}" = "TIMEOUT" ] || [ "${baseline_code}" = "000" ]; then
    fail "baseline failed: kali -> webapp returned '${baseline_code}'. Lab is broken before the test even started."
fi
log "baseline OK (HTTP ${baseline_code})"

# --- step 2: install the temporary rule + AR block --------------------------
log "installing temporary rule + AR block on ${MANAGER}"

# Rule: match webapp's gunicorn access.log line containing the probe
# marker. fired at level 5 to clear any default severity gate.
docker exec "${MANAGER}" sh -c "cat > ${TMP_RULE_FILE} <<'RULES'
<group name=\"aptl,ar_test,\">
  <rule id=\"${TMP_SID}\" level=\"5\">
    <decoded_as>web-accesslog</decoded_as>
    <url>${PROBE_PATH}</url>
    <description>APTL #248 AR test marker - drop ${PROBE_PATH}</description>
  </rule>
</group>
RULES
chown root:wazuh ${TMP_RULE_FILE} 2>/dev/null || true
chmod 660 ${TMP_RULE_FILE} 2>/dev/null || true
"

# AR block: when rule TMP_SID fires on aptl-webapp-agent, run firewall-drop
# with a 120s timeout. The sentinel comments let cleanup_rule remove the
# block surgically without disturbing the rest of ossec.conf.
docker exec "${MANAGER}" sh -c "
cat >> /var/ossec/etc/ossec.conf <<'AR'
${SENTINEL}
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>${TMP_SID}</rules_id>
    <timeout>120</timeout>
  </active-response>
</ossec_config>
${SENTINEL}
AR
"

restart_manager_and_wait

# --- step 3: trigger the rule from kali -------------------------------------
log "triggering rule via kali -> webapp${PROBE_PATH}"
trigger_code=$(curl_from_kali "${PROBE_PATH}")
log "trigger request returned HTTP ${trigger_code} (any code is fine; the rule decodes the URL)"

log "waiting ${WAIT_AR_SEC}s for AR to install iptables drop in ${TARGET}"
deadline=$(( $(date +%s) + WAIT_AR_SEC ))
ar_seen=0
while [ "$(date +%s)" -lt "${deadline}" ]; do
    if docker exec "${TARGET}" iptables -L INPUT -n 2>/dev/null \
        | grep -q "${KALI_SRC_IP}"; then
        ar_seen=1
        break
    fi
    sleep 2
done

if [ "${ar_seen}" -ne 1 ]; then
    log "iptables -L on ${TARGET}:"
    docker exec "${TARGET}" iptables -L INPUT -n 2>&1 | head -20 || true
    fail "AR did not install a drop for ${KALI_SRC_IP} within ${WAIT_AR_SEC}s. Check 'docker exec ${MANAGER} tail -30 /var/ossec/logs/ossec.log' and the agent's logs."
fi
log "AR installed iptables drop for ${KALI_SRC_IP} on ${TARGET}"

# --- step 4: probe again -- should time out --------------------------------
log "probing ${PROBE_PATH} again from kali (expect timeout / RST)"
post_code=$(curl_from_kali "/")
if [ "${post_code}" = "TIMEOUT" ] || [ "${post_code}" = "000" ]; then
    log "follow-up correctly blocked (curl: '${post_code}')"
else
    fail "follow-up was NOT blocked: kali -> webapp/ returned HTTP ${post_code}. AR rule is not enforcing. Check 'docker exec ${TARGET} iptables -L -n -v'."
fi

# --- step 5: cleanup --------------------------------------------------------
cleanup_rule
restart_manager_and_wait
restart_target_and_wait

# --- step 6: sanity (connectivity restored after rule removal) -------------
log "sanity: kali -> webapp after AR cleanup"
recovery_code=$(curl_from_kali "/")
if [ "${recovery_code}" = "TIMEOUT" ] || [ "${recovery_code}" = "000" ]; then
    fail "recovery failed: kali -> webapp returned '${recovery_code}' AFTER cleanup. The temporary AR rule may have left iptables dirty in ${TARGET}."
fi
log "recovery OK (HTTP ${recovery_code})"

log "PASS - in-process Wazuh agent on ${TARGET} successfully blocked kali via AR; default posture restored"
