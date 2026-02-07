#!/bin/bash
# Shared entrypoint functions for APTL lab containers.
# Source this file from container-specific entrypoint.sh scripts.

# Function to setup SSH key for labadmin
setup_labadmin_ssh() {
    echo "Setting up labadmin SSH access..."

    # Ensure .ssh directory exists with correct permissions
    mkdir -p /home/labadmin/.ssh
    chmod 700 /home/labadmin/.ssh
    chown labadmin:labadmin /home/labadmin/.ssh

    # Check multiple sources for SSH key in priority order
    local key_added=false

    # Option 1: Check for file path in environment variable (most common)
    if [ -n "$LABADMIN_SSH_KEY_FILE" ] && [ -f "$LABADMIN_SSH_KEY_FILE" ]; then
        echo "Found SSH key file at $LABADMIN_SSH_KEY_FILE"
        cat "$LABADMIN_SSH_KEY_FILE" >> /home/labadmin/.ssh/authorized_keys
        key_added=true
    fi

    # Option 2: Check for volume-mounted key file (local dev - aptl_lab_key)
    if [ "$key_added" = false ] && [ -f "/keys/aptl_lab_key.pub" ]; then
        echo "Found volume-mounted SSH key at /keys/aptl_lab_key.pub"
        cat /keys/aptl_lab_key.pub >> /home/labadmin/.ssh/authorized_keys
        key_added=true
    fi

    # Option 3: Check for legacy volume-mounted key file (labadmin.pub)
    if [ "$key_added" = false ] && [ -f "/keys/labadmin.pub" ]; then
        echo "Found volume-mounted SSH key at /keys/labadmin.pub"
        cat /keys/labadmin.pub >> /home/labadmin/.ssh/authorized_keys
        key_added=true
    fi

    # Option 4: Check for environment variable (AWS/production)
    if [ "$key_added" = false ] && [ -n "$LABADMIN_SSH_KEY" ]; then
        echo "Found SSH key in LABADMIN_SSH_KEY environment variable"
        echo "$LABADMIN_SSH_KEY" >> /home/labadmin/.ssh/authorized_keys
        key_added=true
    fi

    if [ "$key_added" = true ]; then
        # Set correct permissions
        chmod 600 /home/labadmin/.ssh/authorized_keys
        chown labadmin:labadmin /home/labadmin/.ssh/authorized_keys
        echo "Labadmin SSH key configured successfully"
    else
        echo "WARNING: No SSH key found for labadmin. SSH key auth will not work."
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

        echo "Rsyslog forwarding configured to Wazuh at $SIEM_IP:$SIEM_PORT"

        # Restart rsyslog to load the new configuration
        if systemctl is-active rsyslog >/dev/null 2>&1; then
            echo "Restarting rsyslog to apply forwarding configuration..."
            systemctl restart rsyslog || echo "Warning: Failed to restart rsyslog (may not be running yet)"
        else
            echo "Rsyslog not yet running, will be started by systemd"
        fi
    else
        echo "SIEM forwarding not configured (SIEM_IP not set)"
    fi
}

# Function to setup Wazuh agent environment
setup_wazuh_env() {
    if [ -n "$SIEM_IP" ]; then
        export WAZUH_MANAGER="$SIEM_IP"
        echo "WAZUH_MANAGER set to $WAZUH_MANAGER"

        # Create environment file for systemd service
        echo "WAZUH_MANAGER=$WAZUH_MANAGER" > /etc/environment.wazuh
        echo "INSTALL_WAZUH=${INSTALL_WAZUH:-true}" >> /etc/environment.wazuh
        echo "INSTALL_FALCO=${INSTALL_FALCO:-true}" >> /etc/environment.wazuh
        echo "INSTALL_XSIAM=${INSTALL_XSIAM:-false}" >> /etc/environment.wazuh
    else
        echo "ERROR: SIEM_IP not set - Wazuh agent installation will fail"
        exit 1
    fi
}

# Common entrypoint main sequence - call from container entrypoint.sh
run_common_entrypoint() {
    echo "Container hostname: $(hostname)"
    echo "Container IP: $(hostname -I | awk '{print $1}')"

    setup_labadmin_ssh
    setup_rsyslog
    setup_wazuh_env

    echo "=== Common initialization complete ==="
}
