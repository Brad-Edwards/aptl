# APTL Shared Agent Installation Framework

This directory contains the shared infrastructure for installing EDR agents across all APTL containers based on configuration.

## Overview

The shared framework provides:
- Configuration-based agent installation (reads from `aptl.json`)
- OS-family detection and appropriate script selection
- Support for multiple EDR agents (Wazuh, Falco, XSIAM, etc.)
- Centralized agent installation scripts for each OS family

## Directory Structure

```
shared/
├── agent-config.sh      # Configuration loader - parses aptl.json
├── agent-wrapper.sh     # Main orchestrator - calls appropriate installers
├── agents/              # Agent-specific installation scripts
│   ├── wazuh/
│   │   ├── debian.sh    # For Ubuntu, Debian, Kali
│   │   └── rocky.sh     # For Rocky Linux, RHEL, CentOS
│   ├── falco/
│   │   ├── debian.sh
│   │   └── rocky.sh
│   └── xsiam/
│       ├── debian.sh
│       └── rocky.sh
└── README.md            # This file
```

## Configuration Format

In `aptl.json`, configure agents per container:

```json
{
  "containers": {
    "victim": true,
    "kali": true,
    "reverse": true
  },
  "edr_agents": {
    "victim": ["wazuh", "falco", "xsiam"],
    "kali": ["wazuh"],
    "reverse": ["wazuh", "falco"],
    "default": ["wazuh"]
  },
  "agent_configs": {
    "xsiam": {
      "installer_path": "/files/Brad-Lab-Report_sh.tar.gz",
      "tenant_id": "your-tenant-id"
    }
  }
}
```

## Usage in Containers

To use this shared framework in a container:

1. **Copy shared files during Docker build:**
```dockerfile
# Copy shared agent installation framework
COPY containers/shared /opt/purple-team/shared
RUN chmod +x /opt/purple-team/shared/*.sh

# Copy aptl.json configuration
COPY aptl.json /opt/aptl-config/aptl.json
```

2. **Modify container's install-all.sh:**
```bash
#!/bin/bash
set -e

echo "=== Purple Team Lab Installation Starting ==="

# Check if already installed
if [ -f /opt/aptl/.agents_installed ]; then
    echo "All agents already installed, exiting..."
    exit 0
fi

# Set container type (if not already set)
export CONTAINER_TYPE="victim"  # or kali, reverse, etc.

# Set Wazuh manager from environment
export WAZUH_MANAGER="${SIEM_IP:-172.20.0.10}"

# Set agent name for Wazuh
export AGENT_NAME="${CONTAINER_TYPE}-$(hostname)-$(date +%s)"

# Run the shared agent installation wrapper
/opt/purple-team/shared/agent-wrapper.sh

echo "=== All Purple Team Lab Services Installed ==="
```

3. **Ensure environment variables are set:**
- `WAZUH_MANAGER` or `SIEM_IP` - IP address of Wazuh manager
- `AGENT_NAME` - Unique name for the agent
- `CONTAINER_TYPE` - Type of container (victim, kali, reverse, etc.)

## OS Family Support

The framework automatically detects the OS family:
- **debian**: Ubuntu, Debian, Kali
- **rhel**: Rocky Linux, RHEL, CentOS, AlmaLinux, Fedora
- **alpine**: Alpine Linux

## Adding New Agents

To add support for a new EDR agent:

1. Create installation scripts in `agents/<agent-name>/`:
   - `debian.sh` for Debian-based systems
   - `rocky.sh` for RHEL-based systems
   - `alpine.sh` for Alpine Linux (if needed)

2. Update `agent-wrapper.sh` to handle the new agent

3. Add configuration to `aptl.json`:
   ```json
   "edr_agents": {
     "victim": ["wazuh", "falco", "new-agent"]
   }
   ```

## Environment Variables

The framework uses these environment variables:
- `APTL_CONFIG_FILE` - Path to config file (default: `/opt/aptl-config/aptl.json`)
- `CONTAINER_TYPE` - Container type (auto-detected from hostname if not set)
- `WAZUH_MANAGER` - Wazuh manager IP address (required for Wazuh)
- `AGENT_NAME` - Agent name for registration
- `INSTALL_WAZUH` - Set by config loader
- `INSTALL_FALCO` - Set by config loader
- `INSTALL_XSIAM` - Set by config loader
- `OS_FAMILY` - Detected OS family (debian/rhel/alpine)

## Testing

To test the configuration loader:
```bash
# Source the config loader
source agent-config.sh

# Load config for a specific container
load_agent_config "victim"

# Check what would be installed
echo "Wazuh: $INSTALL_WAZUH"
echo "Falco: $INSTALL_FALCO"
```

## Migration Guide

To migrate an existing container to use this framework:

1. Remove agent-specific installation scripts from container directory
2. Update Dockerfile to copy shared framework
3. Modify install-all.sh to call agent-wrapper.sh
4. Update aptl.json with desired agent configuration
5. Test the container build and runtime installation

## Notes

- Installation scripts are idempotent - they check if already installed
- Failed agent installations are logged but don't stop other agents
- The framework falls back to Wazuh-only if no configuration is found
- Each OS family script handles its specific package manager and setup