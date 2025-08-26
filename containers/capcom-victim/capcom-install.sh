#!/bin/bash
set -e

echo "=== Capcom Victim Installation Starting ==="

# Check if already installed
if [ -f /var/ossec/.capcom_installed ]; then
    echo "Capcom victim services already installed, exiting..."
    exit 0
fi

echo "Step 1: Installing Wazuh Agent..."
export AGENT_NAME="capcom-victim-$(hostname)-$(date +%s)"
/opt/purple-team/scripts/install-wazuh.sh

echo "Step 2: Installing Falco..."
/opt/purple-team/scripts/install-falco.sh

echo "Step 3: Configuring Wazuh with monitoring..."

# Replace placeholders in template and overwrite ossec.conf
sed -e "s/AGENT_NAME_PLACEHOLDER/$AGENT_NAME/g" \
    -e "s/WAZUH_MANAGER_PLACEHOLDER/$WAZUH_MANAGER/g" \
    /opt/purple-team/scripts/ossec.conf.template > /var/ossec/etc/ossec.conf

systemctl restart wazuh-agent

echo "=== All Capcom Victim Services Installed ==="

# Create flag to prevent re-running
touch /var/ossec/.capcom_installed