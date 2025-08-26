#!/bin/bash
set -e

echo "=== Kali Red Team Lab Installation Starting ==="

# Check if already installed
if [ -f /var/ossec/.all_installed ]; then
    echo "All services already installed, exiting..."
    exit 0
fi

echo "Step 1: Installing Wazuh Agent..."
export AGENT_NAME="kali-redteam-$(hostname)-$(date +%s)"
/opt/kali-redteam/scripts/install-wazuh.sh

echo "Step 2: Configuring Wazuh with monitoring..."

# Replace placeholders in template and overwrite ossec.conf
sed -e "s/AGENT_NAME_PLACEHOLDER/$AGENT_NAME/g" \
    -e "s/WAZUH_MANAGER_PLACEHOLDER/$WAZUH_MANAGER/g" \
    /opt/kali-redteam/scripts/ossec.conf.template > /var/ossec/etc/ossec.conf

systemctl restart wazuh-agent

echo "=== All Kali Red Team Lab Services Installed ==="

# Create flag to prevent re-running
touch /var/ossec/.all_installed