# Victim Container

The victim container serves as a target system for red team activities and security testing. It provides a Rocky Linux 9 environment with SSH access, Wazuh agent integration, and Falco runtime security monitoring.

## Container Configuration

- **Base Image**: rockylinux:9
- **User**: `labadmin` with sudo privileges (NOPASSWD)
- **SSH**: Key-based authentication only (port 22, mapped to host 2022)
- **IP Address**: 172.20.0.20

See [containers/victim/Dockerfile](../../containers/victim/Dockerfile) for complete build configuration.

## Security Monitoring

### Wazuh Agent + Falco Integration

The container runs dual security monitoring:

1. **Wazuh Agent**: Connects to manager at 172.20.0.10:1514
2. **Falco Runtime Security**: Modern eBPF syscall monitoring
3. **rsyslog**: Forwards system logs to 172.20.0.10:514

**Installation Scripts:**
- [install-all.sh](../../containers/victim/install-all.sh) - Main installer
- [install-wazuh.sh](../../containers/victim/install-wazuh.sh) - Wazuh agent setup
- [install-falco.sh](../../containers/victim/install-falco.sh) - Falco setup
- [ossec.conf.template](../../containers/victim/ossec.conf.template) - Wazuh config template

### Monitored Data

**Wazuh Agent:**
- File integrity monitoring
- Authentication events (SSH, sudo)
- System logs and command history

**Falco eBPF:**
- Syscall monitoring
- Container escape attempts
- Privilege escalation
- Sensitive file access (/etc/shadow, SSH keys)
- Suspicious process spawning

Falco events are written to `/var/log/falco_events.json` and forwarded to Wazuh by the agent.

## Network Configuration

- **Internal IP**: 172.20.0.20 (static)
- **SSH Port**: 22 (host port 2022)
- **Network**: aptl_aptl-network (Docker bridge)

## Access Methods

```bash
# SSH from host
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022

# Direct container access
docker exec -it aptl-victim /bin/bash
```

## Service Status

```bash
# Check services
docker exec aptl-victim systemctl status sshd wazuh-agent falco

# Check agent connection
docker exec aptl-victim /var/ossec/bin/wazuh-control info
```

## Troubleshooting

**Service Issues:**
```bash
# Check service status
docker exec aptl-victim systemctl status sshd wazuh-agent falco

# Check system logs
docker exec aptl-victim journalctl -xe
```

**Wazuh Agent Issues:**
```bash
# Check agent status
docker exec aptl-victim /var/ossec/bin/wazuh-control status

# Check agent logs
docker exec aptl-victim tail -f /var/ossec/logs/ossec.log

# Test connectivity
docker exec aptl-victim nc -zv 172.20.0.10 1514
```

**Falco Issues:**
```bash
# Check Falco status
docker exec aptl-victim systemctl status falco

# Check Falco logs
docker exec aptl-victim journalctl -u falco

# Test event generation
docker exec aptl-victim cat /etc/shadow
docker exec aptl-victim tail /var/log/falco_events.json
```