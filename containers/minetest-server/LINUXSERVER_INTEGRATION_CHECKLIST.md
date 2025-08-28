# LinuxServer.io Integration Checklist

## Overview
Converting Rocky Linux Minetest container to use LinuxServer.io base image for current Luanti version and VoxeLibre support.

## Critical s6-overlay Service Rules
- **Oneshot services**: Use `up` files with simple commands, NOT `run` files
- **Script execution**: Call separate executable scripts from `up` files
- **Service dependencies**: Use `dependencies` file to order service startup
- **User context**: All scripts run as root initially, use `lsiown` for abc user ownership

## Container Architecture Changes

### Base Image Switch
- [ ] Replace `FROM rockylinux:9` with `FROM lscr.io/linuxserver/baseimage-alpine:3.18`
- [ ] Remove dnf package manager commands
- [ ] Add Alpine apk packages for monitoring integration

### User Model Conversion
- [ ] Remove custom `labadmin` user creation
- [ ] Use LinuxServer.io `abc` user (PUID/PGID mapped)
- [ ] Update SSH configuration for `abc` user
- [ ] Change `chown` commands to `lsiown` for proper user mapping

### Configuration Paths
- [ ] Update Minetest config path to `/config/.minetest/main-config/minetest.conf`
- [ ] Map SSH keys to `/config/.ssh/` directory
- [ ] Use `/config/` for persistent data storage

### s6-overlay Service Structure
- [ ] Create service directories in `root/etc/s6-overlay/s6-rc.d/`
- [ ] **CRITICAL**: Use `up` files with simple commands for oneshot services
- [ ] Place executable scripts in `root/usr/local/bin/`
- [ ] Set proper service dependencies with `dependencies` files
- [ ] Mark services as `oneshot` type in `type` files

### 🔧 Service Implementation Details

#### SSH Access Service (`init-ssh`)
```bash
# File: root/etc/s6-overlay/s6-rc.d/init-ssh/up
/usr/local/bin/init-ssh.sh

# File: root/usr/local/bin/init-ssh.sh
#!/usr/bin/with-contenv bash
setup_ssh_access() {
    mkdir -p /config/.ssh
    chmod 700 /config/.ssh
    lsiown abc:abc /config/.ssh
    
    # Fix abc user shell for SSH login
    sed -i 's|abc:x:1000:1000::/config:/bin/false|abc:x:1000:1000::/config:/bin/bash|' /etc/passwd
}
```

#### Monitoring Service (`init-aptl-monitoring`)
```bash
# File: root/etc/s6-overlay/s6-rc.d/init-aptl-monitoring/up
/usr/local/bin/init-aptl-monitoring.sh

# File: root/usr/local/bin/init-aptl-monitoring.sh
#!/usr/bin/with-contenv bash
# Wazuh agent installation and configuration
# Falco installation 
# Rsyslog forwarding setup
```

#### VoxeLibre Installation (`init-voxelibre`)
```bash
# File: root/etc/s6-overlay/s6-rc.d/init-voxelibre/up
/usr/local/bin/init-voxelibre.sh

# File: root/usr/local/bin/init-voxelibre.sh
#!/usr/bin/with-contenv bash
# Download and install VoxeLibre game content
# Set proper ownership with lsiown abc:abc
```

### ⚠️ Known Issues and Solutions

#### SSH Authentication Fix
- **Issue**: `abc` user has `/bin/false` shell preventing SSH login
- **Solution**: Update `/etc/passwd` to change shell to `/bin/bash`
```bash
sed -i 's|abc:x:1000:1000::/config:/bin/false|abc:x:1000:1000::/config:/bin/bash|' /etc/passwd
```

#### SIEM_IP Environment Variable
- **Issue**: Environment variable not visible inside container
- **Solution**: Verify docker-compose.yml environment section includes SIEM_IP

## Docker Compose Environment
```yaml
environment:
  - PUID=1000
  - PGID=1000
  - TZ=Etc/UTC
  - CLI_ARGS=--gameid devtest
  - SIEM_IP=172.20.0.10
  - LABADMIN_SSH_KEY_FILE=/keys/aptl_lab_key.pub
```

## Testing Checklist

### User Mapping Verification
- [ ] Verify PUID/PGID mapping works: `ls -la /config/` shows `abc:abc` ownership
- [ ] Container can write to mounted volumes with correct permissions

### 🔧 Pending Verification
- [ ] SSH access works: `ssh abc@localhost -p 2026`
- [ ] Wazuh agent connects to manager at 172.20.0.10
- [ ] Falco service starts successfully
- [ ] Minetest server runs with VoxeLibre
- [ ] Rsyslog forwards to SIEM successfully

## Implementation Status
- **Base Architecture**: ⏳ Not started
- **User Model**: ⏳ Not started  
- **s6-overlay Services**: ⏳ Not started
- **SSH Access**: ⏳ Not started
- **Monitoring Integration**: ⏳ Not started
- **VoxeLibre**: ⏳ Not started

## Next Steps
1. Implement executable scripts in `/usr/local/bin/`
2. Fix `abc` user shell for SSH login
3. Convert monitoring installation to Alpine packages
4. Test complete integration
5. Install and configure VoxeLibre game content