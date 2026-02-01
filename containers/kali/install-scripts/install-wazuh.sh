#!/bin/bash
set -e

echo "=== Starting Kali Wazuh Agent Installation ==="

# Verify WAZUH_MANAGER is set
if [ -z "$WAZUH_MANAGER" ]; then
    echo "ERROR: WAZUH_MANAGER environment variable not set"
    exit 1
fi

echo "Installing Wazuh agent with manager: $WAZUH_MANAGER"
echo "Using agent name: $AGENT_NAME"

# Wait for Wazuh manager to be reachable before proceeding
echo "Waiting for Wazuh manager at $WAZUH_MANAGER to be reachable..."
timeout=180
attempt=0
manager_ready=false
while [ $timeout -gt 0 ]; do
    if timeout 2 bash -c "exec 3<>/dev/tcp/$WAZUH_MANAGER/1514 && exec 3<&- && exec 3>&-" 2>/dev/null; then
        echo "Wazuh manager is reachable"
        manager_ready=true
        break
    fi
    attempt=$((attempt + 1))
    if [ $((attempt % 6)) -eq 0 ]; then
        echo "   Still waiting for Wazuh manager... (${timeout}s remaining)"
    fi
    sleep 5
    timeout=$((timeout - 5))
done

if [ "$manager_ready" = false ]; then
    echo "WARNING: Wazuh manager may not be ready, but proceeding with installation..."
    echo "   The agent will retry connection when the service starts"
fi

# Install prerequisites for Debian/Kali
apt-get update
apt-get install -y curl gnupg lsb-release

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
chmod 644 /usr/share/keyrings/wazuh.gpg

# Install Wazuh agent
apt-get update
WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent=4.12.0-1

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
chmod 666 /var/log/bash_history.log

echo "Bash command history logging configured"

# Kill any orphaned processes from installation
echo "Cleaning up any orphaned wazuh processes..."
killall wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector wazuh-modulesd 2>/dev/null || echo "No wazuh processes to kill"

# Clean PID files
echo "Cleaning PID files..."
rm -f /var/ossec/var/run/*.pid

# Start Wazuh agent directly (no systemd)
echo "Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

# Verify agent is running
echo "Verifying Wazuh agent..."
if /var/ossec/bin/wazuh-control status | grep -q "is running"; then
    echo "Wazuh agent is running"
else
    echo "Warning: Wazuh agent may not be fully started yet"
fi

echo "=== Kali Wazuh Agent Installation Complete ==="