# Victim Container Template Guide

## Overview

Guide for creating new victim containers based on the existing victim container template. All victim containers follow established patterns - **reference the actual files rather than duplicating code here**.

## Core Patterns (Reference Files)

### 1. Post-Entrypoint One-Off Service Pattern

**Key Files:**

- Pattern: `containers/victim/lab-install.service` - systemd service template
- Core script: `containers/victim/install-all.sh` - main installation logic  
- Child scripts: `containers/victim/install-wazuh.sh`, `containers/victim/install-falco.sh`
- Base entrypoint: `containers/victim/entrypoint.sh` - SSH/SIEM setup

**Critical Requirements:**

- Service runs once after container boot (use `ConditionPathExists=!` pattern)
- Core script creates completion flag to prevent re-runs
- Must call existing child scripts for Wazuh/Falco
- Enable service in Dockerfile: `systemctl enable [scenario]-install.service`

### 2. SSH Key Multi-Mode Pattern

**Reference:** `containers/victim/entrypoint.sh` lines 6-51

- Handles volume mounts, env vars, file paths
- **Don't duplicate this logic** - call parent entrypoint

### 3. SIEM Integration Pattern

**Reference:** `containers/victim/entrypoint.sh` lines 54-85

- Rsyslog forwarding configuration
- Wazuh environment setup
- **Don't duplicate this logic** - call parent entrypoint

## Container Creation Steps

### 1. Copy Victim Container (Don't Build From Scratch)

**CRITICAL: Copy the entire victim container, don't try to inherit or reference**

```bash
# Copy entire victim directory
cp -r containers/victim containers/[scenario-name]
```

**Why copy instead of inherit:**

- Victim container has complex entrypoint logic, service patterns, install scripts
- Copying preserves all functionality, just requires renaming conflicts
- Inheritance approaches miss critical setup steps

### 2. Rename All Files and References

**CRITICAL: Must rename all victim-specific files and references**

**File Renames Required:**

```bash
cd containers/[scenario-name]
mv install-all.sh [scenario-name]-install.sh
mv lab-install.service [scenario-name]-install.service  
mv validate-victim.sh validate-[scenario-name].sh
```

**Content Updates Required:**

- **Dockerfile**: Update COPY and RUN commands for renamed files
- **Service file**: Update ConditionPathExists and ExecStart paths
- **Install script**: Update agent name and completion flag path
- **Validation script**: Update all variable names and output text
- **Entrypoint.sh**: Update startup message text
- **README.md**: Update container name and scenario references
- **rebuild_container.sh**: Update service name

### 3. Study Existing Patterns (After Copying)

**Required Reading:**

- `containers/victim/Dockerfile` - base container setup
- `containers/victim/entrypoint.sh` - initialization logic
- `containers/victim/lab-install.service` - service pattern
- `containers/victim/install-all.sh` - installation script pattern
- `containers/victim/README.md` - troubleshooting and testing

### 3. Network/Naming Allocation

**Reference:** `docker-compose.yml` victim service block (victim container)

- **Next IP:** Check docker-compose.yml for next available IP (increment from last used)
- **Next Port:** Check docker-compose.yml for next available port (increment from last used)
- **Container:** `aptl-[scenario]-victim`
- **Hostname:** `[scenario]-victim-host`

### 3. Use Existing Utilities

**Rebuild Script Pattern:**

- Copy and adapt `containers/victim/rebuild_container.sh`
- Change service name from `victim` to `[scenario]-victim`

**Validation:**

- Copy and rename `containers/victim/validate-victim.sh` to `validate-[scenario]-server.sh`
- Update all variable names and references from VICTIM_IP to [SCENARIO]_SERVER_IP
- Add scenario-specific checks as needed

**Troubleshooting:**

- Reference `containers/victim/README.md` section "Troubleshooting"
- Adapt commands for your container name

### 4. Docker Compose Integration

**Reference Pattern:** `docker-compose.yml` lines 114-142

- Copy victim block, rename service
- Update IP, port, container name, hostname
- Add `depends_on: [victim]` to ensure main victim starts first
- Add volume for logs: `[scenario]_victim_logs`

## Implementation Checklist

### Pre-Implementation

- [ ] Read all reference files listed above
- [ ] Identify next available IP (172.20.0.X) and port
- [ ] Plan what goes in core script vs child scripts

### Container Files

- [ ] Dockerfile uses copied victim files (no changes needed to entrypoint.sh)
- [ ] One-off service file follows `lab-install.service` pattern
- [ ] Core script follows `install-all.sh` pattern
- [ ] Child scripts for specific components as needed

### Integration  

- [ ] Docker compose entry follows victim pattern
- [ ] Unique naming (container, hostname, IP, port)
- [ ] Volume declaration for logs
- [ ] Copy/adapt `rebuild_container.sh`

### Testing

**IMPORTANT: Docker Compose Project Name**

```bash
# If working from different directory, specify project name to match existing lab
docker compose -p aptl up -d [scenario-victim]

# Check all containers in same project
docker compose -p aptl ps
```

**Test Checklist:**

- [ ] SSH connectivity: `ssh -i ~/.ssh/aptl_lab_key -p [PORT] labadmin@localhost`
- [ ] Service status: `docker exec aptl-[scenario]-victim systemctl status [scenario]-install.service`
- [ ] Installation flag: `docker exec aptl-[scenario]-victim test -f /var/ossec/.[scenario]_installed`
- [ ] Kali connectivity: `ssh kali@localhost -p 2023 "ping -c 2 172.20.0.[X]"`
- [ ] Wazuh agent registered: Check agent ID in Wazuh manager logs
- [ ] CLI logging: Run commands, verify in `/var/ossec/logs/alerts/alerts.json`
- [ ] Falco events: Look for JSON entries with command details
- [ ] Use `validate-victim.sh` with new IP/port for automated checks

### Lab Integration

- [ ] Update `start-lab.sh` SSH tests and connection info
- [ ] `lab_connections.txt` is auto-generated by startup script  
- [ ] Document scenario-specific environment variables

## Key Principles

1. **Reference, don't duplicate** - link to actual files
2. **Parent entrypoint must be called** - don't reimplement SSH/SIEM
3. **One-off service pattern mandatory** - use existing template
4. **Sequential naming/networking** - avoid conflicts
5. **Leverage existing utilities** - rebuild, validate, troubleshoot scripts
