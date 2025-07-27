# Basic CTF Scenario 4: Telnet Weak Authentication

## Overview
Legacy Telnet service with weak authentication and clear-text password transmission. Demonstrates risks of unencrypted remote access protocols and default credentials.

## Scenario Details
- **Difficulty**: Basic (2/10)
- **Attack Vectors**: Telnet authentication, clear-text protocols, default credentials
- **Skills Tested**: Legacy protocol exploitation, credential discovery, command execution
- **Expected Time**: 5-10 minutes

## Setup

### Prerequisites
- Telnet server (telnetd or xinetd)
- User accounts with weak passwords
- System banner configuration

### Setup Script
```bash
#!/bin/bash
# setup_telnet_weak_auth.sh

echo "[+] Setting up Telnet Weak Authentication scenario..."

# Install telnet server
sudo apt-get update -qq
sudo apt-get install -y telnetd xinetd

# Create telnet user accounts with weak passwords
sudo useradd -m -s /bin/bash admin
sudo useradd -m -s /bin/bash guest
sudo useradd -m -s /bin/bash operator
sudo useradd -m -s /bin/bash service

echo "admin:admin" | sudo chpasswd
echo "guest:guest" | sudo chpasswd
echo "operator:password" | sudo chpasswd
echo "service:service123" | sudo chpasswd

# Create flag files
echo "APTL{t3ln3t_w34k_4uth}" | sudo tee /home/admin/flag.txt > /dev/null
echo "APTL{cl34r_t3xt_pr0t0c0l}" | sudo tee /home/operator/system_flag.txt > /dev/null

# Create interesting files
cat << 'EOF' | sudo tee /home/admin/system_info.txt > /dev/null
System Administration Notes
===========================
Default Accounts:
- admin/admin (system administrator)
- guest/guest (guest access)
- operator/password (system operator)
- service/service123 (service account)

Security Note: This system uses legacy telnet for remote access.
Consider upgrading to SSH for encrypted communications.
EOF

echo "System backup and maintenance logs" | sudo tee /home/operator/backup_logs.txt > /dev/null
echo "Guest user welcome information" | sudo tee /home/guest/welcome.txt > /dev/null

# Configure xinetd for telnet
cat << 'EOF' | sudo tee /etc/xinetd.d/telnet > /dev/null
service telnet
{
    disable = no
    flags = REUSE
    socket_type = stream
    wait = no
    user = root
    server = /usr/sbin/in.telnetd
    log_on_failure += USERID
    bind = 0.0.0.0
}
EOF

# Create custom banner
cat << 'EOF' | sudo tee /etc/issue.net > /dev/null
================================================================
    CORPORATE NETWORK SYSTEM - AUTHORIZED ACCESS ONLY
================================================================
Welcome to the Corporate Legacy System (CLS-2019)
System Type: Production Server
Location: Data Center Alpha

WARNING: This system is for authorized users only.
All activities are monitored and logged.

For technical support, contact: support@company.local
Default credentials should be changed after first login.

================================================================
EOF

# Configure telnet to use custom banner
echo 'BANNER_FILE="/etc/issue.net"' | sudo tee -a /etc/default/telnetd > /dev/null

# Set file permissions
sudo chown admin:admin /home/admin/flag.txt
sudo chmod 600 /home/admin/flag.txt
sudo chown operator:operator /home/operator/system_flag.txt
sudo chmod 600 /home/operator/system_flag.txt

# Start services
sudo systemctl restart xinetd
sudo systemctl enable xinetd

# Ensure telnet port is open
sudo ufw allow 23/tcp 2>/dev/null || true

echo "[+] Telnet Weak Authentication scenario deployed!"
echo "[+] Target: Telnet service on port 23"
echo "[+] Test accounts:"
echo "    admin/admin (flag in ~/flag.txt)"
echo "    guest/guest (basic access)"
echo "    operator/password (flag in ~/system_flag.txt)"
echo "    service/service123 (service account)"
echo "[+] Test: telnet localhost"
```

### Manual Setup Steps
1. Install telnet server: `sudo apt-get install telnetd xinetd`
2. Create user accounts with weak passwords
3. Configure xinetd for telnet service
4. Create flag files in user directories
5. Start xinetd service

## Attack Methodology

### Expected Attack Path
1. **Port Scanning**: Discover Telnet service on port 23
2. **Banner Grabbing**: Read system banner for information
3. **Credential Testing**: Try common username/password combinations
4. **Authentication**: Login with discovered credentials
5. **Flag Discovery**: Navigate user directories and find flags

### Key Commands Red Team Will Use
```bash
# Port scanning
nmap -sV -p 23 <target_ip>

# Banner grabbing
nc <target_ip> 23
telnet <target_ip>

# Credential attacks
telnet <target_ip>
# Try combinations:
# admin/admin
# guest/guest
# operator/password
# service/service123
# root/root, admin/123456, etc.

# Automated credential testing
hydra -L users.txt -P passwords.txt telnet://<target_ip>
medusa -h <target_ip> -U users.txt -P passwords.txt -M telnet

# File discovery after login
ls -la
cat flag.txt
find / -name "*flag*" 2>/dev/null
cat /home/*/flag.txt 2>/dev/null
```

## Blue Team Detection Signatures

### Log Patterns to Monitor
```
# Auth logs (/var/log/auth.log)
- Telnet login attempts
- Multiple failed authentications
- Successful logins from unusual sources
- Clear-text password transmission

# Xinetd logs (/var/log/syslog)
- Telnet service connections
- Connection frequency patterns
- Source IP analysis
```

### Detection Rules
```
# Telnet authentication attempts
telnetd: connect from <IP>
login: FAILED LOGIN SESSION FROM <IP>

# Multiple failed attempts
Multiple "authentication failure" from same IP within timeframe

# Successful telnet login
login: LOGIN ON pts/X FROM <IP> by <username>

# Automated attack detection
High frequency connection attempts from single source
Sequential username attempts (admin, guest, operator)

# Clear-text protocol usage
Network traffic on port 23 (unencrypted)
Passwords visible in network captures
```

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_telnet_weak_auth.sh

echo "[+] Cleaning up Telnet Weak Authentication scenario..."

# Stop telnet service
sudo systemctl stop xinetd
sudo systemctl disable xinetd

# Remove telnet configuration
sudo rm -f /etc/xinetd.d/telnet

# Remove user accounts
sudo userdel -r admin 2>/dev/null
sudo userdel -r guest 2>/dev/null
sudo userdel -r operator 2>/dev/null
sudo userdel -r service 2>/dev/null

# Remove custom banner
sudo rm -f /etc/issue.net

# Remove telnet configuration
sudo sed -i '/BANNER_FILE/d' /etc/default/telnetd 2>/dev/null

# Clear auth logs (optional)
# sudo truncate -s 0 /var/log/auth.log

echo "[+] Telnet Weak Authentication scenario cleaned up!"
```

### Manual Cleanup Steps
1. Stop xinetd: `sudo systemctl stop xinetd`
2. Remove user accounts: `sudo userdel -r admin guest operator service`
3. Remove telnet configuration: `sudo rm /etc/xinetd.d/telnet`
4. Remove custom banner: `sudo rm /etc/issue.net`
5. Clear logs (optional)

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_telnet_weak_auth.sh

echo "[+] Resetting Telnet Weak Authentication to basic state..."

# Run cleanup first
./cleanup.sh

# Wait for services to stop
sleep 3

# Run setup again
./setup.sh

echo "[+] Telnet Weak Authentication scenario reset complete!"
```

## Investigation Opportunities

### For Blue Team Analysis
- Clear-text protocol monitoring
- Authentication failure pattern analysis
- Legacy system identification
- Credential attack detection
- Network traffic analysis (unencrypted)

### Learning Objectives
- Legacy protocol security risks
- Clear-text authentication dangers
- Default credential vulnerabilities
- Network traffic analysis
- Secure protocol migration planning

## Security Notes
- Demonstrates risks of unencrypted protocols
- Shows dangers of default/weak credentials
- Should only be deployed in isolated lab environments
- Real systems should use SSH instead of Telnet
- Passwords are transmitted in clear text over network

## Advanced Analysis Opportunities

### Network Traffic Analysis
- Capture clear-text passwords with Wireshark/tcpdump
- Analyze telnet protocol communications
- Demonstrate packet-level credential exposure
- Show why encrypted protocols (SSH) are essential

### Automated Attack Detection
- Configure fail2ban for telnet protection
- Set up real-time monitoring for legacy protocols
- Create alerts for authentication anomalies
- Demonstrate security monitoring best practices