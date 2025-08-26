#!/bin/bash
set -e

echo "=== Installing Wazuh Agent on Kali Red Team Container ==="

# Verify WAZUH_MANAGER is set
if [ -z "$WAZUH_MANAGER" ]; then
    echo "ERROR: WAZUH_MANAGER environment variable not set"
    exit 1
fi

echo "Installing Wazuh agent with manager: $WAZUH_MANAGER"

# Install prerequisites for Debian/Kali
apt-get update
apt-get install -y curl gnupg lsb-release

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
chmod 644 /usr/share/keyrings/wazuh.gpg

# Install Wazuh agent
apt-get update
WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent

echo "Wazuh agent installed successfully"

# Configure enhanced bash logging for red team activities
echo "Configuring bash command logging..."
cat >> /etc/bash.bashrc << 'EOF'

# Enhanced bash history logging for red team monitoring
export HISTFILE=/var/log/kali_bash_history.log
export HISTFILESIZE=50000
export HISTSIZE=50000  
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
export PROMPT_COMMAND="history -a"
shopt -s histappend

# Log all commands with context for red team monitoring
log_kali_command() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') KALI_USER=$USER PWD=$PWD COMMAND=$BASH_COMMAND" >> /var/log/kali_bash_history.log 2>/dev/null || true
}
trap 'log_kali_command' DEBUG
EOF

# Create log files with proper permissions
touch /var/log/kali_bash_history.log
chmod 644 /var/log/kali_bash_history.log

echo "Bash command history logging configured"

# Enable Wazuh agent (will start via systemd in entrypoint)
systemctl enable wazuh-agent

echo "Wazuh agent configuration complete"