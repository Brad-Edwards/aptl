#!/bin/bash
# Install wazuh-agent on a Debian/Ubuntu container (issue #248).
#
# Factored from the sidecar's previous inline Dockerfile RUN so the four
# in-process target containers (webapp, fileshare, ad, dns) and the
# remaining sidecar share one source of truth for the apt-repo + key +
# package install sequence.
#
# Designed to be run during image build via:
#   COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
#   RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh
#
# Does NOT install supervisor or purge build dependencies. Each calling
# Dockerfile owns those choices — sidecar trims `curl gnupg` for image
# size; in-process targets keep them because their primary service
# typically needs them too.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    lsb-release \
    ca-certificates \
    procps \
    netcat-openbsd \
    jq \
    iptables

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update
WAZUH_MANAGER=PLACEHOLDER apt-get install -y wazuh-agent=4.12.0-1

apt-get clean
rm -rf /var/lib/apt/lists/*

# Active-response wrapper + kali whitelist (issue #249, ADR-021). If
# the calling Dockerfile pre-COPYed the wrapper script and whitelist
# file into /tmp before running this installer, place them in the
# canonical AR locations on the agent. This keeps the per-Dockerfile
# boilerplate to three COPYs + one RUN; the install logic lives in
# one place.
WRAPPER_SRC=/tmp/aptl-firewall-drop.sh
WHITELIST_SRC=/tmp/active-response-whitelist
if [ -f "${WRAPPER_SRC}" ]; then
    # Use `install -D` to create parent dirs as needed (the agent
    # package's bin dir always exists, but be explicit for safety).
    install -D -m 0755 -o root -g wazuh "${WRAPPER_SRC}" /var/ossec/active-response/bin/aptl-firewall-drop
fi
if [ -f "${WHITELIST_SRC}" ]; then
    # `/var/ossec/etc/lists/` doesn't exist in a fresh wazuh-agent
    # install (manager creates it for CDB lists; agents don't have
    # it by default). `install -D` creates the lists/ dir at mode 0755
    # owned by root:root, then drops the file with the right perms.
    install -D -m 0640 -o root -g wazuh "${WHITELIST_SRC}" /var/ossec/etc/lists/active-response-whitelist
fi
