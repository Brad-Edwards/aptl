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

### 1. Study Existing Patterns
**Required Reading:**
- `containers/victim/Dockerfile` - base container setup
- `containers/victim/entrypoint.sh` - initialization logic
- `containers/victim/lab-install.service` - service pattern
- `containers/victim/install-all.sh` - installation script pattern
- `containers/victim/README.md` - troubleshooting and testing

### 2. Network/Naming Allocation
**Reference:** `docker-compose.yml` lines 114-142 (victim container)
- **Next IP:** 172.20.0.21 (increment from 172.20.0.20)
- **Next Port:** 2024 (increment from 2022)
- **Container:** `aptl-[scenario]-victim`
- **Hostname:** `[scenario]-victim-host`

### 3. Use Existing Utilities

**Rebuild Script Pattern:**
- Copy and adapt `containers/victim/rebuild_container.sh`
- Change service name from `victim` to `[scenario]-victim`

**Validation:**
- Use existing `containers/victim/validate-victim.sh`
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
- [ ] Dockerfile inherits from victim context
- [ ] Custom entrypoint calls parent `entrypoint.sh`
- [ ] One-off service file follows `lab-install.service` pattern
- [ ] Core script follows `install-all.sh` pattern
- [ ] Child scripts for specific components as needed

### Integration  
- [ ] Docker compose entry follows victim pattern
- [ ] Unique naming (container, hostname, IP, port)
- [ ] Volume declaration for logs
- [ ] Copy/adapt `rebuild_container.sh`

### Testing
- [ ] Use `validate-victim.sh` with new IP/port
- [ ] SSH connectivity: `ssh -i keys/aptl_lab_key -p [PORT] labadmin@localhost`
- [ ] Service status: `systemctl status [scenario]-install.service`
- [ ] Installation flag: `test -f /var/ossec/.scenario_installed`
- [ ] Kali connectivity from 172.20.0.30
- [ ] SIEM logs in Wazuh dashboard

### Documentation
- [ ] Update `lab_connections.txt` with new access details
- [ ] Document scenario-specific environment variables
- [ ] Add to main project documentation

## Key Principles
1. **Reference, don't duplicate** - link to actual files
2. **Parent entrypoint must be called** - don't reimplement SSH/SIEM
3. **One-off service pattern mandatory** - use existing template
4. **Sequential naming/networking** - avoid conflicts
5. **Leverage existing utilities** - rebuild, validate, troubleshoot scripts