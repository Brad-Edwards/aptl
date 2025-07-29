#!/bin/bash
set -e

# Configure rsyslog based on environment variables
if [ -n "$SIEM_PRIVATE_IP" ] && [ -n "$SIEM_TYPE" ]; then
    echo "Configuring red team log forwarding to $SIEM_TYPE SIEM..."
    
    if [ "$SIEM_TYPE" = "splunk" ]; then
        # Configure rsyslog for Splunk (port 5514)
        cat >> /etc/rsyslog.conf << EOF
# APTL Red Team Log Forwarding - Splunk
# Route red team logs to aptl-redteam index
:msg, contains, "REDTEAM_LOG" @@$SIEM_PRIVATE_IP:5514
EOF
    else
        # Configure rsyslog for qRadar (port 514)
        cat >> /etc/rsyslog.conf << EOF
# APTL Red Team Log Forwarding - qRadar
# Red team logs identified by source IP in qRadar
:msg, contains, "REDTEAM_LOG" @@$SIEM_PRIVATE_IP:514
EOF
    fi
    
    # Validate IP addresses before substitution
    validate_ip() {
        if [[ $1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            return 0
        else
            return 1
        fi
    }
    
    # Update scripts with actual SIEM and victim IPs
    if [ -n "$VICTIM_PRIVATE_IP" ]; then
        if validate_ip "$VICTIM_PRIVATE_IP"; then
            sed -i "s/\${victim_private_ip}/$VICTIM_PRIVATE_IP/g" /home/kali/*.sh
        else
            echo "Warning: Invalid VICTIM_PRIVATE_IP format: $VICTIM_PRIVATE_IP"
        fi
    fi
    
    if validate_ip "$SIEM_PRIVATE_IP"; then
        sed -i "s/\${siem_private_ip}/$SIEM_PRIVATE_IP/g" /home/kali/*.sh
    else
        echo "Warning: Invalid SIEM_PRIVATE_IP format: $SIEM_PRIVATE_IP"
    fi
    
    # SIEM_TYPE validation (only allow expected values)
    if [[ "$SIEM_TYPE" =~ ^(splunk|qradar)$ ]]; then
        sed -i "s/\${siem_type}/$SIEM_TYPE/g" /home/kali/*.sh
    else
        echo "Warning: Invalid SIEM_TYPE: $SIEM_TYPE"
    fi
    
    echo "Red team log forwarding configured for $SIEM_TYPE"
else
    echo "SIEM not configured - skipping red team log configuration"
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
if [ -n "$SIEM_PRIVATE_IP" ]; then
    if ! grep -q "redteam_logging.sh" /home/kali/.bashrc; then
        cat >> /home/kali/.bashrc << EOF

# APTL Red Team Logging Functions
source ~/redteam_logging.sh
EOF
    fi
fi

# Ensure proper ownership
chown -R kali:kali /home/kali/

echo "=== APTL Kali Red Team Container Ready ==="
echo "SSH: ssh kali@<container_ip>"
echo "Working directory: /home/kali/operations"
if [ -n "$SIEM_PRIVATE_IP" ]; then
    echo "SIEM: $SIEM_TYPE ($SIEM_PRIVATE_IP)"
fi

# Execute the main command
exec "$@"