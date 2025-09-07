# APTL Gaming API Container

This directory contains the gaming API container for the Purple Team Lab credential stuffing demo.

## Architecture

The victim containers support dual deployment modes:
1. **Local Development**: Uses volume-mounted SSH keys
2. **AWS Production**: Uses environment variables

Both modes use the same container image and entrypoint script, ensuring consistency.

## Local Development Setup

### 1. Generate Lab Admin SSH Key
```bash
# Generate dedicated keypair for lab admin access
ssh-keygen -t ed25519 -f ~/.ssh/aptl-labadmin -C "labadmin@aptl"
```

### 2. Build and Run Locally
```bash
# Build the base image
docker build -t aptl-victim:latest .

# Run with local compose file
docker-compose -f docker-compose.local.yml up -d

# Access victim container
ssh -i ~/.ssh/aptl-labadmin -p 2222 labadmin@localhost
```

### 3. Test Log Collection
```bash
# View collected logs from local rsyslog collector
docker-compose -f docker-compose.local.yml logs rsyslog-collector
docker exec aptl-rsyslog-collector cat /var/log/collected.log
```

## AWS Production Setup

### 1. Create .env File
```bash
cat > .env << EOF
ECR_REGISTRY=123456789012.dkr.ecr.us-east-1.amazonaws.com
LABADMIN_SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... labadmin@aptl"
SIEM_PRIVATE_IP=10.0.1.100
SIEM_TYPE=qradar
EOF
```

### 2. Deploy on Container Host
```bash
# This would typically be done by user_data script
docker-compose -f docker-compose.aws.yml up -d
```

## How the Dual Mode Works

The `entrypoint.sh` script checks for SSH keys in this order:
1. Volume mount at `/keys/labadmin.pub` (local dev)
2. `LABADMIN_SSH_KEY` environment variable (production)
3. File path in `LABADMIN_SSH_KEY_FILE` environment variable (alternative)

This allows the same image to work in both environments without modification.

## Container Scenarios

### Base Victim
- Standard RHEL-based system
- SSH, HTTP, FTP services
- Weak users (if enabled)

### Web Victim
- DVWA, WebGoat installations
- Additional web vulnerabilities
- PHP, MySQL services

### SSH Victim
- Weak SSH configurations
- Multiple authentication methods
- Brute-force targets

### Multi-Service Victim
- Multiple vulnerable services
- Telnet, FTP, SMB
- Simulates legacy systems

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `LABADMIN_SSH_KEY` | SSH public key for lab admin | `ssh-ed25519 AAAA...` |
| `SIEM_IP` | SIEM server IP for log forwarding | `10.0.1.100` |
| `SIEM_TYPE` | Type of SIEM (qradar/splunk) | `qradar` |
| `SIEM_PORT` | SIEM syslog port (optional) | `514` |
| `ENABLE_WEAK_USERS` | Create users with weak passwords | `true` |
| `SCENARIO` | Victim scenario type | `web`, `ssh`, `multi` |

## Testing

### Local Testing Checklist
- [ ] Container starts successfully
- [ ] Can SSH as labadmin with key
- [ ] Services are running (check with `systemctl status`)
- [ ] Logs are being generated
- [ ] Rsyslog collector receives logs (if enabled)

### Production Testing Checklist  
- [ ] Container pulls from ECR
- [ ] SSH key from environment variable works
- [ ] Logs forward to SIEM
- [ ] All services accessible from Kali container
- [ ] Resource usage is acceptable

## Troubleshooting

### SSH Access Issues
```bash
# Check if key was properly installed
docker exec aptl-victim-base cat /home/labadmin/.ssh/authorized_keys

# Check SSH logs
docker exec aptl-victim-base journalctl -u sshd -f
```

### Log Forwarding Issues
```bash
# Check rsyslog configuration
docker exec aptl-victim-base cat /etc/rsyslog.d/90-forward.conf

# Test manual log entry
docker exec aptl-victim-base logger "TEST: Manual log entry"

# Check rsyslog status
docker exec aptl-victim-base systemctl status rsyslog
```

### Service Issues
```bash
# Check all services
docker exec aptl-victim-base systemctl list-units --failed

# Restart a service
docker exec aptl-victim-base systemctl restart httpd
```