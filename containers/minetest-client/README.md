# APTL Minetest Client Container

This directory contains the minetest client container for the Purple Team Lab memory scanning demo.

## Architecture

The minetest client container supports dual deployment modes:
1. **Local Development**: Uses volume-mounted SSH keys
2. **AWS Production**: Uses environment variables

## Base Configuration

Built on Rocky Linux 9 with:
- SSH access (labadmin user)
- Wazuh SIEM agent integration
- Falco runtime security monitoring
- Systemd service management
- Rsyslog forwarding to Wazuh Manager

## Usage

### Local Development

```bash
docker build -t aptl-minetest-client:latest .
```

### Container Access

```bash
# Access minetest client container
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2025
```

## Network Configuration

- **Container IP**: 172.20.0.23
- **SSH Port**: 2025
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
docker exec aptl-minetest-client cat /home/labadmin/.ssh/authorized_keys
```

### SSH Service
```bash
docker exec aptl-minetest-client journalctl -u sshd -f
```

### Log Forwarding
```bash
docker exec aptl-minetest-client cat /etc/rsyslog.d/90-forward.conf
```

### Test Logging
```bash
docker exec aptl-minetest-client logger "TEST: Manual log entry"
```

### Rsyslog Status
```bash
docker exec aptl-minetest-client systemctl status rsyslog
```

### Service Issues
```bash
docker exec aptl-minetest-client systemctl list-units --failed
```