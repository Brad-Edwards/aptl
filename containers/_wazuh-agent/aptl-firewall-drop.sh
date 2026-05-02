#!/bin/bash
# APTL active-response: standalone iptables drop with kali whitelist
# (issue #249, ADR-021).
#
# This is a self-contained replacement for Wazuh's upstream
# `firewall-drop` script, NOT a wrapper. Forwarding stdin to a separate
# upstream process breaks Wazuh's stateful AR protocol — wazuh-execd
# can keep the channel open after the initial JSON to support a
# `check_keys` handshake, and a forwarding wrapper that buffers stdin
# would deadlock or break the dialogue. By implementing the iptables
# operation directly, the wrapper owns the stdin contract end-to-end.
#
# Wazuh sends one JSON object per invocation on stdin (stateless mode,
# Wazuh 4.x default for simple add/delete commands):
#
#     {"version":1,"command":"add","parameters":{"alert":{"data":{"srcip":"..."}}}}
#
# We read the first JSON object, extract `command` and
# `parameters.alert.data.srcip`, validate srcip as a literal IPv4
# (defends against decoder-injected newlines that would let an
# attacker spoof a whitelist hit), consult the flat-file whitelist at
# /var/ossec/etc/lists/active-response-whitelist, and either
# short-circuit (whitelisted on `add`) or run the iptables operation.
# `delete` (cleanup) ALWAYS runs, regardless of whitelist — drops
# installed before an IP joined the whitelist still get reaped on
# schedule.
#
# Override points (for tests): APTL_AR_WHITELIST, APTL_AR_LOG,
# APTL_AR_IPTABLES (path to the iptables binary; tests can point this
# at /bin/true to avoid mutating the lab's iptables).

set -euo pipefail

WHITELIST="${APTL_AR_WHITELIST:-/var/ossec/etc/lists/active-response-whitelist}"
LOG="${APTL_AR_LOG:-/var/ossec/logs/active-responses.log}"
IPTABLES="${APTL_AR_IPTABLES:-/usr/sbin/iptables}"

# Validate SRCIP is a single dotted-decimal IPv4 with no control
# characters. A Wazuh decoder that pulls srcip from a hostile log line
# could embed a newline + a whitelisted IP; without validation,
# `grep -Fxq` treats multi-line input as multiple patterns and would
# short-circuit on the embedded whitelisted line. The regex permits
# only `<octet>.<octet>.<octet>.<octet>` with each octet 0-255.
_is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local oct
    for oct in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        if [ "${#oct}" -gt 1 ] && [ "${oct:0:1}" = "0" ]; then return 1; fi
        if [ "$oct" -gt 255 ]; then return 1; fi
    done
    return 0
}

_log() {
    # Append a single timestamped line to the AR log. Errors are
    # tolerated (e.g., the log dir might be read-only on some
    # configurations); the AR itself proceeds either way.
    printf '%s aptl-firewall-drop: %s\n' "$(date -Iseconds)" "$*" \
        >> "${LOG}" 2>/dev/null || true
}

# Read one JSON object from stdin. Wazuh 4.x sends one object per
# invocation as a single line; the trailing newline is optional. The
# `|| [ -n "$line" ]` clause catches the no-final-newline case, where
# `read -r` returns 1 but still populates `$line`. We use the first
# non-empty line and ignore subsequent lines (which would only appear
# in stateful AR mode; the standalone implementation here doesn't
# support that mode and exits after the first message).
INPUT=""
while IFS= read -r line || [ -n "${line:-}" ]; do
    if [ -n "${line}" ]; then
        INPUT="${line}"
        break
    fi
done

if [ -z "${INPUT}" ]; then
    _log "no JSON received on stdin"
    exit 1
fi

# Extract command + srcip via jq if available, else a python3 fallback.
_extract() {
    local key="$1"
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "${INPUT}" | jq -r "${key}" 2>/dev/null || printf ''
    elif command -v python3 >/dev/null 2>&1; then
        printf '%s' "${INPUT}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    parts = '${key}'.lstrip('.').split('.')
    for p in parts:
        d = d.get(p, '') if isinstance(d, dict) else ''
    print(d if d else '')
except Exception:
    pass
" 2>/dev/null
    else
        printf ''
    fi
}

COMMAND=$(_extract '.command')
SRCIP=$(_extract '.parameters.alert.data.srcip')

# Sanity check: the IPv4 validator runs after parsing so a malformed
# srcip never reaches the whitelist match or the iptables call.
if ! _is_valid_ipv4 "${SRCIP}"; then
    _log "rejecting invalid srcip: ${SRCIP@Q}"
    exit 0
fi

# Whitelist check applies ONLY to `add`. `delete` (cleanup) must run
# unconditionally so timeout-driven cleanups happen even for IPs that
# joined the whitelist after a drop was installed.
if [ "${COMMAND}" = "add" ] && [ -f "${WHITELIST}" ]; then
    if grep -Fxq -- "${SRCIP}" "${WHITELIST}" 2>/dev/null; then
        _log "SKIPPED for whitelisted ${SRCIP}"
        exit 0
    fi
fi

case "${COMMAND}" in
    add)
        # Idempotent insert: if the rule is already present (e.g., from
        # a previous AR invocation that didn't time out yet), we don't
        # add a duplicate — Wazuh agents may dispatch the same `add`
        # multiple times across reconnects.
        if "${IPTABLES}" -C INPUT -s "${SRCIP}" -j DROP >/dev/null 2>&1; then
            _log "rule already present for ${SRCIP}; no-op"
            exit 0
        fi
        if "${IPTABLES}" -I INPUT 1 -s "${SRCIP}" -j DROP; then
            _log "added DROP for ${SRCIP}"
        else
            _log "iptables insert FAILED for ${SRCIP} (rc=$?)"
            exit 1
        fi
        ;;
    delete)
        # Remove every matching rule — Wazuh's delete is "remove the
        # most recent add", but we are conservative and clean all
        # exact-match rules to avoid leaks. If a delete FAILS while
        # the matching rule is still present (`iptables -C` succeeds
        # but `iptables -D` fails), exit non-zero so wazuh-execd
        # surfaces the cleanup failure — otherwise the manager
        # believes cleanup succeeded while the DROP rule remains.
        removed=0
        delete_rc=0
        while "${IPTABLES}" -C INPUT -s "${SRCIP}" -j DROP >/dev/null 2>&1; do
            if "${IPTABLES}" -D INPUT -s "${SRCIP}" -j DROP; then
                removed=$((removed + 1))
            else
                rc=$?
                _log "iptables delete FAILED for ${SRCIP} (rc=${rc})"
                delete_rc=${rc}
                break
            fi
        done
        _log "removed ${removed} DROP rule(s) for ${SRCIP}"
        if [ "${delete_rc}" -ne 0 ]; then
            exit "${delete_rc}"
        fi
        ;;
    *)
        _log "unknown command: ${COMMAND@Q}"
        exit 1
        ;;
esac

exit 0
