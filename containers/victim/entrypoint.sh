#!/bin/bash
set -e

echo "=== Purple Team Lab Victim Container Starting ==="

# Function to setup SSH key for labadmin
setup_labadmin_ssh() {
    echo "Setting up labadmin SSH access..."
    
    # Ensure .ssh directory exists with correct permissions
    mkdir -p /home/labadmin/.ssh
    chmod 700 /home/labadmin/.ssh
    chown labadmin:labadmin /home/labadmin/.ssh
    
    # Check multiple sources for SSH key in priority order
    local key_added=false
    
    # Option 1: Check for volume-mounted key file (local dev)
    if [ -f "/keys/labadmin.pub" ]; then
        echo "Found volume-mounted SSH key at /keys/labadmin.pub"
        cat /keys/labadmin.pub >> /home/labadmin/.ssh/authorized_keys
        key_added=true
    fi
    
    # Option 2: Check for environment variable (AWS/production)
    if [ -n "$LABADMIN_SSH_KEY" ]; then
        echo "Found SSH key in LABADMIN_SSH_KEY environment variable"
        echo "$LABADMIN_SSH_KEY" >> /home/labadmin/.ssh/authorized_keys
        key_added=true
    fi
    
    # Option 3: Check for file path in environment variable
    if [ -n "$LABADMIN_SSH_KEY_FILE" ] && [ -f "$LABADMIN_SSH_KEY_FILE" ]; then
        echo "Found SSH key file at $LABADMIN_SSH_KEY_FILE"
        cat "$LABADMIN_SSH_KEY_FILE" >> /home/labadmin/.ssh/authorized_keys
        key_added=true
    fi
    
    if [ "$key_added" = true ]; then
        # Set correct permissions
        chmod 600 /home/labadmin/.ssh/authorized_keys
        chown labadmin:labadmin /home/labadmin/.ssh/authorized_keys
        echo "✅ Labadmin SSH key configured successfully"
    else
        echo "⚠️  WARNING: No SSH key found for labadmin. SSH key auth will not work."
        echo "   Expected one of:"
        echo "   - Volume mount at /keys/labadmin.pub"
        echo "   - LABADMIN_SSH_KEY environment variable"
        echo "   - File path in LABADMIN_SSH_KEY_FILE environment variable"
    fi
}

# Function to configure rsyslog forwarding
setup_rsyslog() {
    if [ -n "$SIEM_IP" ]; then
        echo "Configuring rsyslog to forward to Wazuh at $SIEM_IP..."
        
        # Default to Wazuh syslog port
        SIEM_PORT="${SIEM_PORT:-514}"
        
        # Create rsyslog forwarding config for Wazuh
        cat > /etc/rsyslog.d/90-forward.conf << EOF
# Purple Team Lab - Forward all logs to Wazuh SIEM
*.* @${SIEM_IP}:${SIEM_PORT}
EOF
        
        echo "✅ Rsyslog forwarding configured to Wazuh at $SIEM_IP:$SIEM_PORT"
    else
        echo "ℹ️  SIEM forwarding not configured (SIEM_IP not set)"
    fi
}

# Base image has no scenario-specific setup
# Scenario-specific users will be added by derived containers

# Main execution
echo "Container hostname: $(hostname)"
echo "Container IP: $(hostname -I | awk '{print $1}')"

# Setup labadmin SSH access
setup_labadmin_ssh

# Configure rsyslog if SIEM details provided
setup_rsyslog

echo "=== Container initialization complete ==="

# Execute the main command (typically systemd)
exec "$@"