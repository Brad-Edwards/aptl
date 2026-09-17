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
dnf clean all
rm -rf /var/cache/dnf
