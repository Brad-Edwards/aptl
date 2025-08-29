#!/bin/bash
set -e

echo "=== Purple Team Lab Installation Starting ==="

# Check if already installed
if [ -f /opt/lab/.minecraft-server_installed ]; then
    echo "All services already installed, exiting..."
    exit 0
fi

# Update package lists first
export DEBIAN_FRONTEND=noninteractive
apt-get update

echo "Step 1: Installing Wazuh Agent..."
export AGENT_NAME="minecraft-server-$(hostname)-$(date +%s)"
/opt/purple-team/scripts/install-wazuh.sh

echo "Step 2: Installing Falco..."
/opt/purple-team/scripts/install-falco.sh

echo "Step 3: Configuring Wazuh with monitoring..."

# Replace placeholders in template and overwrite ossec.conf
sed -e "s/AGENT_NAME_PLACEHOLDER/$AGENT_NAME/g" \
    -e "s/WAZUH_MANAGER_PLACEHOLDER/$WAZUH_MANAGER/g" \
    /opt/purple-team/scripts/ossec.conf.template > /var/ossec/etc/ossec.conf

systemctl restart wazuh-agent

echo "=== All Purple Team Lab Services Installed ==="

echo "Step 4: Installing and configuring minecraft server..."
/opt/purple-team/scripts/setup-gameserver.sh

# Create flag to prevent re-running
mkdir -p /opt/lab
touch /opt/lab/.minecraft-server_installed