#!/bin/bash
set -e

# Function to setup Wazuh agent environment
setup_wazuh_env() {
    if [ -n "$SIEM_IP" ]; then
        export WAZUH_MANAGER="$SIEM_IP"
        echo "WAZUH_MANAGER set to $WAZUH_MANAGER"
        
        # Create environment file for systemd service
        echo "WAZUH_MANAGER=$WAZUH_MANAGER" > /etc/environment.wazuh
    else
        echo "ERROR: SIEM_IP not set - Wazuh agent installation will fail"
        exit 1
    fi
}

# Configure rsyslog based on environment variables
if [ -n "$SIEM_IP" ]; then
    echo "Configuring red team log forwarding to Wazuh SIEM..."
    
    # Configure rsyslog for Wazuh (port 514)
    cat >> /etc/rsyslog.conf << EOF
# APTL Red Team Log Forwarding - Wazuh
# Route red team logs to Wazuh
:msg, contains, "REDTEAM_LOG" @@$SIEM_IP:514
EOF
    
    # Validate IP addresses before substitution
    validate_ip() {
        if [[ $1 =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$ ]]; then
            return 0
        else
            return 1
        fi
    }
    
    # Update scripts with actual SIEM and victim IPs
    if [ -n "$VICTIM_IP" ]; then
        if validate_ip "$VICTIM_IP"; then
            sed -i "s/\${victim_ip}/$VICTIM_IP/g" /home/kali/*.sh
        else
            echo "Warning: Invalid VICTIM_IP format: $VICTIM_IP"
        fi
    fi
    
    if validate_ip "$SIEM_IP"; then
        sed -i "s/\${siem_ip}/$SIEM_IP/g" /home/kali/*.sh
    else
        echo "Warning: Invalid SIEM_IP format: $SIEM_IP"
    fi
    
    echo "Red team log forwarding configured for Wazuh"
else
    echo "SIEM_IP not configured - skipping red team log configuration"
fi

# Start rsyslog
if command -v rsyslogd >/dev/null 2>&1; then
    rsyslogd
    echo "rsyslog started"
else
    echo "rsyslog not available"
fi

# Set up SSH keys from host
if [ -f "/host-ssh-keys/authorized_keys" ]; then
    mkdir -p /home/kali/.ssh
    cp /host-ssh-keys/authorized_keys /home/kali/.ssh/authorized_keys
    chown -R kali:kali /home/kali/.ssh
    chmod 700 /home/kali/.ssh
    chmod 600 /home/kali/.ssh/authorized_keys
    echo "SSH keys configured for kali user"
fi

# Start SSH service  
if [ ! -d "/run/sshd" ]; then
    mkdir -p /run/sshd
fi

# Additional setup can be added here if needed

# Source red team logging functions in kali user's bashrc
if [ -n "$SIEM_IP" ]; then
    if ! grep -q "redteam_logging.sh" /home/kali/.bashrc; then
        cat >> /home/kali/.bashrc << EOF

# APTL Red Team Logging Functions
source ~/redteam_logging.sh
EOF
    fi
fi

# Ensure proper ownership
chown -R kali:kali /home/kali/

# Setup Wazuh environment for systemd service
setup_wazuh_env

echo "=== APTL Kali Red Team Container Ready ==="
echo "SSH: ssh kali@<container_ip>"
echo "Working directory: /home/kali/operations"
if [ -n "$SIEM_IP" ]; then
    echo "SIEM: Wazuh ($SIEM_IP)"
fi

# Execute the main command
exec "$@"