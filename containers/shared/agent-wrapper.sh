#!/bin/bash
# Agent Installation Wrapper for APTL
# Orchestrates the installation of configured EDR agents

set -e

echo "=== APTL Agent Installation Wrapper ==="

# Get the directory where this script is located
SHARED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the configuration loader
source "$SHARED_DIR/agent-config.sh"

# Determine container name from hostname or environment variable
CONTAINER_NAME="${CONTAINER_TYPE:-$(hostname | cut -d'-' -f1)}"
echo "Container type: $CONTAINER_NAME"

# Load configuration for this container
load_agent_config "$CONTAINER_NAME"

# Check if we have the right OS family scripts
if [ "$OS_FAMILY" = "unknown" ]; then
    echo "ERROR: Unable to detect OS family"
    exit 1
fi

# Function to install an agent
install_agent() {
    local agent_name="$1"
    local install_flag="$2"
    local script_path="$SHARED_DIR/agents/$agent_name/${OS_FAMILY}.sh"
    
    if [ "$install_flag" = "true" ]; then
        echo "Installing $agent_name agent..."
        
        if [ ! -f "$script_path" ]; then
            echo "WARNING: Installation script not found for $agent_name on $OS_FAMILY: $script_path"
            echo "Skipping $agent_name installation"
            return 1
        fi
        
        # Make script executable
        chmod +x "$script_path"
        
        # Execute the installation script
        if "$script_path"; then
            echo "$agent_name agent installed successfully"
        else
            echo "ERROR: Failed to install $agent_name agent"
            return 1
        fi
    else
        echo "Skipping $agent_name installation (not configured)"
    fi
}

# Install configured agents in order
echo "Beginning agent installations..."

# Install Wazuh if configured
if [ "$INSTALL_WAZUH" = "true" ]; then
    if [ -z "$WAZUH_MANAGER" ]; then
        echo "ERROR: WAZUH_MANAGER environment variable not set"
        exit 1
    fi
    install_agent "wazuh" "$INSTALL_WAZUH"
fi

# Install Falco if configured
install_agent "falco" "$INSTALL_FALCO"

# Install XSIAM if configured
if [ "$INSTALL_XSIAM" = "true" ]; then
    if [ -z "$XSIAM_INSTALLER" ] || [ ! -f "$XSIAM_INSTALLER" ]; then
        echo "WARNING: XSIAM installer not found at: $XSIAM_INSTALLER"
        echo "Skipping XSIAM installation"
    else
        install_agent "xsiam" "$INSTALL_XSIAM"
    fi
fi

echo "=== Agent Installation Complete ==="

# Create completion marker
mkdir -p /opt/aptl
touch /opt/aptl/.agents_installed

# Summary
echo "Installation Summary:"
echo "  - Wazuh: $([ "$INSTALL_WAZUH" = "true" ] && echo "Installed" || echo "Skipped")"
echo "  - Falco: $([ "$INSTALL_FALCO" = "true" ] && echo "Installed" || echo "Skipped")"
echo "  - XSIAM: $([ "$INSTALL_XSIAM" = "true" ] && echo "Installed" || echo "Skipped")"