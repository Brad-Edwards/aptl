#!/bin/bash
set -e

echo "=== Starting Wazuh Agent Installation ==="

# Verify WAZUH_MANAGER is set
if [ -z "$WAZUH_MANAGER" ]; then
    echo "ERROR: WAZUH_MANAGER environment variable not set"
    exit 1
fi

echo "Installing Wazuh agent with manager: $WAZUH_MANAGER"

# Set up Wazuh repository
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
EOF

# Install Wazuh agent
WAZUH_MANAGER="$WAZUH_MANAGER" dnf install -y wazuh-agent

echo "Wazuh agent installed successfully"

# Kill any orphaned processes from RPM installation
echo "Cleaning up any orphaned wazuh processes..."
killall wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector wazuh-modulesd 2>/dev/null || echo "No wazuh processes to kill"

# Clean PID files
echo "Cleaning PID files..."
rm -f /var/ossec/var/run/*.pid

# Start Wazuh agent using wazuh-control
echo "Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

# Verify services are running
echo "Verifying Wazuh services..."
ps aux | grep wazuh | grep -v grep

echo "=== Wazuh Agent Installation Complete ==="

# Create flag file to prevent re-running
touch /var/ossec/.installed