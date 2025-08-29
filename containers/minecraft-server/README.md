# APTL Minecraft Server Container

This directory contains the minecraft server container for the Purple Team Lab.

## Architecture

The minecraft server container supports dual deployment modes:

1. **Local Development**: Uses volume-mounted SSH keys
2. **AWS Production**: Uses environment variables

## Base Configuration

Built on Ubuntu 22.04 with:

- SSH access (labadmin user)
- Wazuh SIEM agent integration
- Falco runtime security monitoring
- Systemd service management
- Rsyslog forwarding to Wazuh Manager

## Usage

### Local Development

```bash
docker build -t aptl-minecraft-server:latest .
```

### Container Access

```bash
# Access minecraft server container
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2026
```

## Network Configuration

- **Container IP**: 172.20.0.26
- **SSH Port**: 2026
- **Minecraft Port**: 25565
- **SIEM Integration**: Logs forwarded to wazuh.manager (172.20.0.10)

## Services

All containers include the standardized service stack:

### Core Services

- **SSH Server**: Remote access and MCP integration
- **Wazuh Agent**: SIEM telemetry and alerts  
- **Falco**: Runtime security monitoring
- **Rsyslog**: Log forwarding to SIEM

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SIEM_IP` | Wazuh Manager IP | `172.20.0.10` |
| `LABADMIN_SSH_KEY_FILE` | SSH public key path | `/keys/aptl_lab_key.pub` |

## Troubleshooting

### SSH Access

```bash
docker exec aptl-minecraft-server cat /home/labadmin/.ssh/authorized_keys
```

### SSH Service

```bash
docker exec aptl-minecraft-server journalctl -u sshd -f
```

### Log Forwarding

```bash
docker exec aptl-minecraft-server cat /etc/rsyslog.d/90-forward.conf
```

### Test Logging

```bash
docker exec aptl-minecraft-server logger "TEST: Manual log entry"
```

### Rsyslog Status

```bash
docker exec aptl-minecraft-server systemctl status rsyslog
```

### Service Issues

```bash
docker exec aptl-minecraft-server systemctl list-units --failed
```
