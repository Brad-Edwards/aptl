#!/bin/bash
# Agent Configuration Loader for APTL
# Reads aptl.json and determines which agents to install for a container

set -e

# Function to detect OS family
detect_os_family() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|kali|kali-rolling)
                echo "debian"
                ;;
            rocky|rhel|centos|fedora|almalinux)
                echo "rhel"
                ;;
            alpine)
                echo "alpine"
                ;;
            *)
                echo "unknown"
                ;;
        esac
    else
        echo "unknown"
    fi
}

# Function to check if jq is available, if not use python
parse_json() {
    local json_file="$1"
    local query="$2"
    
    if command -v jq &> /dev/null; then
        jq -r "$query" < "$json_file"
    elif command -v python3 &> /dev/null; then
        python3 -c "
import json
import sys
with open('$json_file', 'r') as f:
    data = json.load(f)
query = '$query'.replace('.', '').replace('[', \"['\").replace(']', \"']\")
result = eval('data' + query)
if isinstance(result, list):
    print(' '.join(result))
elif result is None:
    print('')
else:
    print(result)
"
    else
        echo "ERROR: Neither jq nor python3 available for JSON parsing" >&2
        return 1
    fi
}

# Function to load agent configuration for a specific container
load_agent_config() {
    local container_name="$1"
    local config_file="${APTL_CONFIG_FILE:-/opt/aptl-config/aptl.json}"
    
    # Export OS family for use by other scripts
    export OS_FAMILY=$(detect_os_family)
    echo "Detected OS family: $OS_FAMILY"
    
    # Check if config file exists
    if [ ! -f "$config_file" ]; then
        echo "WARNING: Configuration file $config_file not found"
        echo "Defaulting to standard agent installation (Wazuh only)"
        export INSTALL_WAZUH="true"
        export INSTALL_FALCO="false"
        export INSTALL_XSIAM="false"
        return 0
    fi
    
    echo "Loading configuration from $config_file for container: $container_name"
    
    # Check if edr_agents section exists
    if ! parse_json "$config_file" '.edr_agents' &>/dev/null; then
        echo "No edr_agents configuration found, using defaults"
        export INSTALL_WAZUH="true"
        export INSTALL_FALCO="false"
        export INSTALL_XSIAM="false"
        return 0
    fi
    
    # Get agents list for this container
    agents=$(parse_json "$config_file" ".edr_agents.$container_name" 2>/dev/null || echo "")
    
    if [ -z "$agents" ]; then
        echo "No specific agent configuration for $container_name, checking defaults..."
        # Check for default configuration
        agents=$(parse_json "$config_file" ".edr_agents.default" 2>/dev/null || echo "wazuh")
    fi
    
    echo "Agents configured for $container_name: $agents"
    
    # Set installation flags
    export INSTALL_WAZUH="false"
    export INSTALL_FALCO="false"
    export INSTALL_XSIAM="false"
    
    for agent in $agents; do
        case "$agent" in
            wazuh)
                export INSTALL_WAZUH="true"
                ;;
            falco)
                export INSTALL_FALCO="true"
                ;;
            xsiam)
                export INSTALL_XSIAM="true"
                # Load XSIAM specific configuration
                export XSIAM_INSTALLER=$(parse_json "$config_file" ".agent_configs.xsiam.installer_path" 2>/dev/null || echo "")
                export XSIAM_TENANT_ID=$(parse_json "$config_file" ".agent_configs.xsiam.tenant_id" 2>/dev/null || echo "")
                ;;
        esac
    done
    
    echo "Agent installation configuration:"
    echo "  - Wazuh: $INSTALL_WAZUH"
    echo "  - Falco: $INSTALL_FALCO"
    echo "  - XSIAM: $INSTALL_XSIAM"
}

# If sourced with arguments, run the load function
if [ "$#" -gt 0 ]; then
    load_agent_config "$1"
fi