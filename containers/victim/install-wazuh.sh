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

# Configure Wazuh command monitoring for process and network monitoring
echo "Configuring process and network monitoring..."
# Insert monitoring config before the closing </ossec_config> tag
sed -i '/<\/ossec_config>/i\
\
  <!-- Process monitoring - check every 60 seconds -->\
  <localfile>\
    <log_format>full_command<\/log_format>\
    <command>ps -auxwwf<\/command>\
    <frequency>60<\/frequency>\
    <alias>process_list<\/alias>\
  <\/localfile>\
\
  <!-- Network connections monitoring - check every 120 seconds -->\
  <localfile>\
    <log_format>full_command<\/log_format>\
    <command>ss -tuln<\/command>\
    <frequency>120<\/frequency>\
    <alias>network_connections<\/alias>\
  <\/localfile>\
\
  <!-- Command history monitoring for shell activity -->\
  <localfile>\
    <log_format>syslog<\/log_format>\
    <location>\/var\/log\/bash_history.log<\/location>\
    <alias>bash_history<\/alias>\
  <\/localfile>\
' /var/ossec/etc/ossec.conf

echo "Process and network monitoring configured"

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
systemctl start wazuh-agent

# Verify service is running
echo "Verifying Wazuh agent service..."
systemctl is-active wazuh-agent && echo "✅ Wazuh agent service is active" || echo "❌ Wazuh agent service failed to start"

echo "=== Wazuh Agent Installation Complete ==="

# Create flag file to prevent re-running
touch /var/ossec/.installed