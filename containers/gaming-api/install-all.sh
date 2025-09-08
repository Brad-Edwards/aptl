#!/bin/bash
set -e

echo "=== Purple Team Lab Installation Starting ==="

# Check if already installed
if [ -f /var/ossec/.all_installed ]; then
    echo "All services already installed, exiting..."
    exit 0
fi

# Set agent name for Wazuh
export AGENT_NAME="gaming-api-$(hostname)-$(date +%s)"

# Install agents based on environment variables
echo "Agent installation configuration:"
echo "  - Wazuh: $INSTALL_WAZUH"
echo "  - Falco: $INSTALL_FALCO"  
echo "  - XSIAM: $INSTALL_XSIAM"

if [ "$INSTALL_WAZUH" = "true" ]; then
    echo "Installing Wazuh agent..."
    /opt/purple-team/scripts/install-wazuh.sh
fi

if [ "$INSTALL_FALCO" = "true" ]; then
    echo "Installing Falco..."
    /opt/purple-team/scripts/install-falco.sh
fi

if [ "$INSTALL_XSIAM" = "true" ]; then
    echo "XSIAM installation not yet implemented"
fi

# Configure Wazuh with custom monitoring settings (if Wazuh was installed)
if [ -f /var/ossec/etc/ossec.conf ] && [ -f /opt/purple-team/scripts/ossec.conf.template ]; then
    echo "Applying custom Wazuh configuration..."
    sed -e "s/AGENT_NAME_PLACEHOLDER/$AGENT_NAME/g" \
        -e "s/WAZUH_MANAGER_PLACEHOLDER/$WAZUH_MANAGER/g" \
        /opt/purple-team/scripts/ossec.conf.template > /var/ossec/etc/ossec.conf
    
    systemctl restart wazuh-agent || true
fi

echo "=== All Purple Team Lab Services Installed ==="

# Mark as installed
mkdir -p /var/ossec
touch /var/ossec/.all_installed