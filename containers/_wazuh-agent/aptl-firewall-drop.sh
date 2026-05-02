#!/bin/bash
# APTL active-response wrapper for `firewall-drop` (issue #249, ADR-021).
#
# Wazuh manager dispatches AR commands by name; the agent's wazuh-execd
# runs the named script in /var/ossec/active-response/bin/. This wrapper
# replaces a direct reference to `firewall-drop` so:
#
#   1. We can consult the kali-IP whitelist before applying any drop —
#      preserving purple-team continuity (ADR-021). Blue can still
#      detect+alert on kali, but `firewall-drop` against a whitelisted
#      source is a no-op.
#   2. Cleanup (`command=delete`) ALWAYS forwards. If a drop was
#      installed before an IP joined the whitelist, the timeout-driven
#      cleanup must still run; otherwise iptables state leaks across
#      iterations.
#
# Wazuh 4.x sends one JSON object per invocation on stdin:
#
#     {"version":1,"command":"add","parameters":{"alert":{"data":{"srcip":"..."}}}}
#
# We extract `command` and `parameters.alert.data.srcip`, consult the
# flat-file whitelist at /var/ossec/etc/lists/active-response-whitelist
# (one IP per line; `#` comments allowed; matched literally with grep
# -Fxq), and either short-circuit (whitelisted on `add`) or forward.
#
# Forwarding strategy: re-emit stdin to the upstream `firewall-drop`.
# Wazuh AR scripts read stdin once; we already consumed it to extract
# fields, so we hold the original payload and pipe it forward.
#
# Override points (for tests): APTL_AR_WHITELIST, APTL_AR_ORIGINAL,
# APTL_AR_LOG.

set -euo pipefail

WHITELIST="${APTL_AR_WHITELIST:-/var/ossec/etc/lists/active-response-whitelist}"
ORIGINAL="${APTL_AR_ORIGINAL:-/var/ossec/active-response/bin/firewall-drop}"
LOG="${APTL_AR_LOG:-/var/ossec/logs/active-responses.log}"

INPUT=$(cat)

# Extract command + srcip via jq if available, falling back to a small
# Python one-liner. jq is in the agent image (added by install.sh in
# #249); the python fallback covers manual ad-hoc runs from a shell
# that may not have jq.
_extract() {
    local key="$1"
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$INPUT" | jq -r "$key" 2>/dev/null || printf ''
    elif command -v python3 >/dev/null 2>&1; then
        printf '%s' "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    parts = '$key'.lstrip('.').split('.')
    for p in parts:
        if isinstance(d, dict):
            d = d.get(p, '')
        else:
            d = ''
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

# Validate SRCIP is a single dotted-decimal IPv4 with no control
# characters. A Wazuh decoder that pulls srcip from a hostile log line
# could embed a newline + a whitelisted IP; without validation,
# `grep -Fxq` treats multi-line input as multiple patterns and would
# short-circuit on the embedded whitelisted line. The regex permits
# only `<octet>.<octet>.<octet>.<octet>` with each octet 0-255, no
# trailing whitespace, no other characters.
_is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local oct
    for oct in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        # Reject leading zeros except literal "0"; reject octets > 255.
        if [ "${#oct}" -gt 1 ] && [ "${oct:0:1}" = "0" ]; then return 1; fi
        if [ "$oct" -gt 255 ]; then return 1; fi
    done
    return 0
}

# Only the `add` command may be short-circuited. `delete` must always
# forward so timeouts clean up rules installed before the IP joined the
# whitelist. Also require SRCIP to validate as a single IPv4 — a
# decoder-injected newline or extra characters would otherwise let an
# attacker spoof a whitelist hit.
if [ "${COMMAND}" = "add" ] && _is_valid_ipv4 "${SRCIP}" && [ -f "${WHITELIST}" ]; then
    if grep -Fxq -- "${SRCIP}" "${WHITELIST}" 2>/dev/null; then
        # Belt-and-braces: only log if the log dir is writable; the
        # agent runs as root so this should always succeed inside the
        # container.
        if [ -w "$(dirname "${LOG}")" ] || [ -w "${LOG}" ] 2>/dev/null; then
            printf '%s aptl-firewall-drop: SKIPPED for whitelisted %s\n' \
                "$(date -Iseconds)" "${SRCIP}" >> "${LOG}" 2>/dev/null || true
        fi
        exit 0
    fi
fi

# Forward to the upstream firewall-drop.
printf '%s' "${INPUT}" | exec "${ORIGINAL}"
