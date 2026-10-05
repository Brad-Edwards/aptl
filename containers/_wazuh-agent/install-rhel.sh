#!/bin/bash
# Install the backend-selected Wazuh agent implementation on an EL-family base.
set -euo pipefail

# EL9 minimal images provide curl-minimal.  Requesting the full curl package
# conflicts with that installed provider and is unnecessary for importing the
# repository key below.
dnf install -y ca-certificates procps-ng iptables
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
install -D -m 0644 /tmp/wazuh.repo /etc/yum.repos.d/wazuh.repo
WAZUH_MANAGER=PLACEHOLDER dnf install -y wazuh-agent-4.12.0-1
# The agent must not run ahead of the 4.12 manager. Exclude it from its only
# repository so an image or node-level `dnf upgrade` keeps the pinned version
# (issue #1193).
echo 'exclude=wazuh-agent' >> /etc/yum.repos.d/wazuh.repo
dnf clean all
rm -rf /var/cache/dnf

# Active-response wrapper + whitelist: the same shared, required step the
# Debian installer runs (issue #1006).
sh /tmp/install-active-response.sh
