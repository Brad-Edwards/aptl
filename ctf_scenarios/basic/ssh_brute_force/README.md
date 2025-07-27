# Basic CTF Scenario 2: SSH Brute Force

## Overview
Classic SSH brute force scenario with weak credentials. Provides excellent training for both password attacks and authentication monitoring.

## Scenario Details
- **Difficulty**: Basic
- **Attack Vectors**: SSH brute force, weak password exploitation
- **Skills Tested**: Password attacks, service enumeration
- **Expected Time**: 5-10 minutes

## Setup

### Prerequisites
- SSH server (OpenSSH)
- User account with weak password

### Setup Script
```bash
#!/bin/bash
# setup_ssh_brute_force.sh

echo "[+] Setting up SSH Brute Force scenario..."

# Install SSH if not present
sudo apt-get update -qq
sudo apt-get install -y openssh-server

# Create vulnerable user account
sudo useradd -m -s /bin/bash ctfuser
echo "ctfuser:password123" | sudo chpasswd

# Create flag file in user's home
echo "APTL{ssh_brut3_f0rc3_succ3ss}" | sudo tee /home/ctfuser/flag.txt > /dev/null
sudo chown ctfuser:ctfuser /home/ctfuser/flag.txt
sudo chmod 600 /home/ctfuser/flag.txt

# Configure SSH for the scenario
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Allow password authentication and create permissive config
cat << 'EOF' | sudo tee -a /etc/ssh/sshd_config > /dev/null

# CTF Scenario Configuration
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 10
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Start SSH service
sudo systemctl start ssh
sudo systemctl enable ssh

# Add some decoy users with stronger passwords
sudo useradd -m -s /bin/bash admin
echo "admin:$(openssl rand -base64 32)" | sudo chpasswd

sudo useradd -m -s /bin/bash backup
echo "backup:$(openssl rand -base64 32)" | sudo chpasswd

echo "[+] SSH Brute Force scenario deployed!"
echo "[+] Target: SSH service on port 22"
echo "[+] Vulnerable user: ctfuser"
echo "[+] Password: password123"
echo "[+] Flag location: /home/ctfuser/flag.txt"
```

### Manual Setup Steps
1. Install OpenSSH server: `sudo apt-get install openssh-server`
2. Create user `ctfuser` with password `password123`
3. Place flag in `/home/ctfuser/flag.txt`
4. Configure SSH to allow password authentication
5. Start SSH service

## Attack Methodology

### Expected Attack Path
1. **Reconnaissance**: Port scan discovers SSH service
2. **User Enumeration**: Attempt to identify valid usernames
3. **Brute Force Attack**: 
   - Manual password attempts
   - Automated brute force with hydra/medusa
4. **Flag Retrieval**: Login and retrieve flag

### Key Commands Red Team Will Use
```bash
# Port scanning
nmap -sV -p 22 <target_ip>

# SSH user enumeration
ssh <target_ip> -l root
ssh <target_ip> -l admin
ssh <target_ip> -l user

# Manual brute force attempts
ssh ctfuser@<target_ip>
# Try common passwords: password, 123456, password123, etc.

# Automated brute force
hydra -l ctfuser -P /usr/share/wordlists/rockyou.txt ssh://<target_ip>
medusa -h <target_ip> -u ctfuser -P /usr/share/wordlists/common-passwords.txt -M ssh

# Flag retrieval after successful login
ssh ctfuser@<target_ip>
cat ~/flag.txt
```

## Blue Team Detection Signatures

### Log Patterns to Monitor
```
# SSH authentication logs (/var/log/auth.log)
- Multiple failed login attempts
- Rapid succession of authentication attempts
- Failed attempts for multiple usernames
- Successful login after failed attempts
```

### Detection Rules
```
# Multiple failed SSH attempts
Failed password for * from <IP> > 5 in 60 seconds

# SSH brute force pattern
authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<IP> user=*

# Successful login after failures
Accepted password for ctfuser from <IP> (after previous failures)

# Multiple username attempts
Failed password for [root|admin|user|guest] from same IP

# Automated tool detection
Large number of rapid connection attempts from single IP
```

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_ssh_brute_force.sh

echo "[+] Cleaning up SSH Brute Force scenario..."

# Remove vulnerable user and decoy users
sudo userdel -r ctfuser 2>/dev/null
sudo userdel -r admin 2>/dev/null
sudo userdel -r backup 2>/dev/null

# Restore SSH configuration
if [ -f /etc/ssh/sshd_config.backup ]; then
    sudo mv /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    sudo systemctl reload ssh
fi

# Clear auth logs (optional - comment out to preserve for analysis)
# sudo truncate -s 0 /var/log/auth.log

echo "[+] SSH Brute Force scenario cleaned up!"
echo "[+] Note: SSH service is still running with original configuration"
```

### Manual Cleanup Steps
1. Delete users: `sudo userdel -r ctfuser admin backup`
2. Restore SSH config: `sudo mv /etc/ssh/sshd_config.backup /etc/ssh/sshd_config`
3. Reload SSH: `sudo systemctl reload ssh`
4. Clear auth logs (optional): `sudo truncate -s 0 /var/log/auth.log`

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_ssh_brute_force.sh

echo "[+] Resetting SSH Brute Force to basic state..."

# Run cleanup first
./cleanup_ssh_brute_force.sh

# Wait a moment for services to settle
sleep 3

# Run setup again
./setup_ssh_brute_force.sh

echo "[+] SSH Brute Force scenario reset complete!"
```

## Investigation Opportunities

### For Blue Team Analysis
- Authentication failure patterns
- Brute force detection and timing
- User enumeration attempts
- Source IP analysis and geolocation
- Attack tool fingerprinting
- Successful compromise indicators

### Advanced Analysis
- Failed login clustering by time/source
- Password pattern analysis
- Correlation with other services
- Baseline authentication vs. attack patterns
- Response time analysis

### Learning Objectives
- SSH security fundamentals
- Authentication log analysis
- Brute force attack detection
- Incident response to credential attacks
- Forensic timeline reconstruction

## Security Notes
- Uses deliberately weak password for educational purposes
- Isolated lab environment only
- Monitor for lateral movement after initial compromise
- Consider implementing fail2ban for advanced detection scenarios