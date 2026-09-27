#!/bin/sh
# Place the APTL active-response wrapper and whitelist on a Wazuh agent
# (issue #249, ADR-021; made mandatory and shared in issue #1006).
#
# Every agent image stages both files in /tmp and runs its distribution's
# installer, which calls this script last. It used to live inside the Debian
# installer as an optional "if the file is there" step; the RHEL installer
# never had it, so RHEL-based agents shipped without the wrapper and the
# configured firewall-drop response could not run. One script, required by
# both installers, and a missing asset is a build failure rather than an agent
# that silently cannot respond.
#
# Paths are overridable only so tests can exercise this script against a
# scratch root; images use the defaults.
set -eu

WRAPPER_SRC="${APTL_AR_WRAPPER_SRC:-/tmp/aptl-firewall-drop.sh}"
WHITELIST_SRC="${APTL_AR_WHITELIST_SRC:-/tmp/active-response-whitelist}"
OSSEC_ROOT="${APTL_AR_OSSEC_ROOT:-/var/ossec}"
AR_GROUP="${APTL_AR_GROUP:-wazuh}"

for asset in "${WRAPPER_SRC}" "${WHITELIST_SRC}"; do
    if [ ! -f "${asset}" ]; then
        echo "active-response asset missing: ${asset}" >&2
        exit 1
    fi
done

# `install -D` creates parent directories; agents have no lists/ directory
# until something puts one there.
install -D -m 0755 -o root -g "${AR_GROUP}" \
    "${WRAPPER_SRC}" "${OSSEC_ROOT}/active-response/bin/aptl-firewall-drop"
install -D -m 0640 -o root -g "${AR_GROUP}" \
    "${WHITELIST_SRC}" "${OSSEC_ROOT}/etc/lists/active-response-whitelist"
