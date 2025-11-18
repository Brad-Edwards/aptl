#!/bin/bash
set -e

echo "=== Starting Wazuh Agent Installation ==="

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
    # Check if we can reach the manager on port 1514 (agent registration port)
    # Use bash's built-in TCP redirection feature in a subshell
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
WAZUH_MANAGER="$WAZUH_MANAGER" dnf install -y wazuh-agent-4.12.0

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

# Kill any orphaned processes from RPM installation
echo "Cleaning up any orphaned wazuh processes..."
killall wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector wazuh-modulesd 2>/dev/null || echo "No wazuh processes to kill"

# Clean PID files
echo "Cleaning PID files..."
rm -f /var/ossec/var/run/*.pid

# Enable and start Wazuh agent using systemctl
echo "Enabling and starting Wazuh agent service..."
systemctl enable wazuh-agent

# Start the service with retry logic
echo "Starting Wazuh agent service..."
max_retries=3
retry_count=0
while [ $retry_count -lt $max_retries ]; do
    if systemctl start wazuh-agent; then
        echo "Wazuh agent service started successfully"
        break
    else
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            echo "   Failed to start, retrying in 5 seconds... (attempt $retry_count/$max_retries)"
            sleep 5
        else
            echo "   Failed to start after $max_retries attempts"
        fi
    fi
done

# Verify service is running
echo "Verifying Wazuh agent service..."
if systemctl is-active wazuh-agent >/dev/null 2>&1; then
    echo "Wazuh agent service is active"
    # Give it a moment to connect to manager
    sleep 3
    # Check if agent is connecting (this is informational, not a failure)
    if [ -f /var/ossec/var/run/wazuh-agentd.pid ]; then
        echo "Wazuh agent process is running"
    fi
else
    echo "WARNING: Wazuh agent service failed to start"
    echo "   This may be normal if Wazuh manager is not yet ready"
    echo "   The service will retry automatically when manager becomes available"
fi

echo "=== Wazuh Agent Installation Complete ==="

