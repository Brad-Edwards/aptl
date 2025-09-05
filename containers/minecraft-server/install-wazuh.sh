#!/bin/bash
set -e

echo "=== Starting Wazuh Agent Installation (Ubuntu) ==="

# Verify WAZUH_MANAGER is set
if [ -z "$WAZUH_MANAGER" ]; then
    echo "ERROR: WAZUH_MANAGER environment variable not set"
    exit 1
fi

echo "Installing Wazuh agent with manager: $WAZUH_MANAGER"
echo "Using agent name: $AGENT_NAME"

# Install required packages
apt-get update
apt-get install -y curl gnupg lsb-release

# Set up Wazuh repository for Ubuntu 22.04
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

# Update package information
apt-get update

# Install Wazuh agent 
WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent

echo "Wazuh agent installed successfully"

# Configure bash history logging
echo "Configuring bash command history logging..."
cat >> /etc/profile << 'EOF'

# Enhanced bash history logging for security monitoring
export HISTFILE=/var/log/bash_history.log
export HISTFILESIZE=10000
export HISTSIZE=10000
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
export PROMPT_COMMAND="history -a"
shopt -s histappend

# Function to log commands with user context
log_command() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') USER=$USER PWD=$PWD COMMAND=$BASH_COMMAND" >> /var/log/bash_history.log 2>/dev/null || true
}
trap 'log_command' DEBUG

EOF

# Create bash history log file with proper permissions
touch /var/log/bash_history.log
chmod 644 /var/log/bash_history.log

echo "Bash command history logging configured"

# Kill any orphaned processes from installation
echo "Cleaning up any orphaned wazuh processes..."
killall wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector wazuh-modulesd 2>/dev/null || echo "No wazuh processes to kill"

# Clean PID files
echo "Cleaning PID files..."
rm -f /var/ossec/var/run/*.pid

# Enable and start Wazuh agent using systemctl
echo "Enabling and starting Wazuh agent service..."
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Verify service is running
echo "Verifying Wazuh agent service..."
systemctl is-active wazuh-agent && echo "Wazuh agent service is active" || echo "Wazuh agent service failed to start"

echo "=== Wazuh Agent Installation Complete ==="