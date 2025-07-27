# Basic CTF Scenario 3: FTP Anonymous Access

## Overview
Classic FTP server misconfiguration allowing anonymous access to sensitive files. Perfect introduction to file transfer protocol reconnaissance and data exfiltration techniques.

## Scenario Details
- **Difficulty**: Basic (1/10)
- **Attack Vectors**: FTP anonymous login, file enumeration, data exfiltration
- **Skills Tested**: FTP protocol basics, file system navigation, data discovery
- **Expected Time**: 5-10 minutes

## Setup

### Prerequisites
- VSFTPd FTP server
- Anonymous access configuration
- File system with hidden flags

### Setup Script
```bash
#!/bin/bash
# setup_ftp_anonymous_access.sh

echo "[+] Setting up FTP Anonymous Access scenario..."

# Install VSFTPd if not present
sudo apt-get update -qq
sudo apt-get install -y vsftpd

# Create FTP directory structure
sudo mkdir -p /srv/ftp/public
sudo mkdir -p /srv/ftp/uploads
sudo mkdir -p /srv/ftp/backups
sudo mkdir -p /srv/ftp/documents

# Create flag files
echo "APTL{ftp_4n0nym0us_4cc3ss}" | sudo tee /srv/ftp/public/flag.txt > /dev/null
echo "APTL{d4t4_3xf1ltr4t10n_m4st3r}" | sudo tee /srv/ftp/backups/hidden_flag.txt > /dev/null

# Create decoy files
echo "Welcome to the company FTP server!" | sudo tee /srv/ftp/public/welcome.txt > /dev/null
echo "Employee handbook and policies" | sudo tee /srv/ftp/documents/handbook.pdf > /dev/null
echo "System backup from $(date)" | sudo tee /srv/ftp/backups/system_backup.log > /dev/null
echo "Temporary upload directory" | sudo tee /srv/ftp/uploads/readme.txt > /dev/null

# Create interesting files that hint at other systems
cat << 'EOF' | sudo tee /srv/ftp/documents/network_info.txt > /dev/null
Company Network Information
===========================
Web Server: 192.168.1.10
Database Server: 192.168.1.20  
File Server: 192.168.1.30 (you are here)
Mail Server: 192.168.1.40

FTP Access:
- Public files available via anonymous login
- Employee files require authentication
EOF

# Configure VSFTPd for anonymous access
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.backup
cat << 'EOF' | sudo tee /etc/vsftpd.conf > /dev/null
# VSFTPd Configuration for CTF Scenario
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=NO
write_enable=NO
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

# Anonymous access configuration
anon_root=/srv/ftp
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
no_anon_password=YES
anon_world_readable_only=YES

# Directory listing
ls_recurse_enable=YES
hide_ids=NO
EOF

# Set proper permissions
sudo chown -R ftp:ftp /srv/ftp/
sudo chmod -R 755 /srv/ftp/
sudo chmod 644 /srv/ftp/public/flag.txt
sudo chmod 644 /srv/ftp/backups/hidden_flag.txt

# Start FTP service
sudo systemctl start vsftpd
sudo systemctl enable vsftpd

echo "[+] FTP Anonymous Access scenario deployed!"
echo "[+] Target: FTP service on port 21"
echo "[+] Access: anonymous login (no password)"
echo "[+] Flags: /public/flag.txt, /backups/hidden_flag.txt"
echo "[+] Test: ftp localhost"
```

### Manual Setup Steps
1. Install VSFTPd: `sudo apt-get install vsftpd`
2. Configure anonymous access in `/etc/vsftpd.conf`
3. Create directory structure in `/srv/ftp/`
4. Place flags in accessible directories
5. Start VSFTPd service

## Attack Methodology

### Expected Attack Path
1. **Port Scanning**: Discover FTP service on port 21
2. **FTP Connection**: Connect with anonymous credentials
3. **Directory Enumeration**: Navigate and list directories
4. **File Discovery**: Find and download flag files
5. **Data Exfiltration**: Extract sensitive information

### Key Commands Red Team Will Use
```bash
# Port scanning
nmap -sV -p 21 <target_ip>

# FTP connection
ftp <target_ip>
# Username: anonymous
# Password: (empty or any email)

# Directory navigation
ftp> ls
ftp> ls -la
ftp> cd public
ftp> cd backups
ftp> cd documents

# File operations
ftp> get flag.txt
ftp> get hidden_flag.txt
ftp> get network_info.txt
ftp> mget *

# Alternative tools
wget -r ftp://anonymous@<target_ip>/
curl ftp://anonymous@<target_ip>/public/
lftp -e "mirror; quit" ftp://anonymous@<target_ip>/
```

## Blue Team Detection Signatures

### Log Patterns to Monitor
```
# VSFTPd logs (/var/log/vsftpd.log)
- Anonymous login attempts
- File download activities
- Directory listing operations
- Automated tool user agents

# System logs (/var/log/syslog)
- FTP service connections
- File access patterns
- Large data transfers
```

### Detection Rules
```
# Anonymous FTP logins
vsftpd: ANONYMOUS FTP login from <IP>

# Multiple file downloads
Multiple GET requests from single IP in short timeframe

# Directory enumeration
Rapid succession of LIST/NLST commands

# Automated tool detection
User-Agent patterns: wget, curl, lftp
Recursive download patterns

# Suspicious file access
Access to backup directories
Download of sensitive file types (.log, .txt, .pdf)
```

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_ftp_anonymous_access.sh

echo "[+] Cleaning up FTP Anonymous Access scenario..."

# Stop FTP service
sudo systemctl stop vsftpd
sudo systemctl disable vsftpd

# Restore original configuration
if [ -f /etc/vsftpd.conf.backup ]; then
    sudo mv /etc/vsftpd.conf.backup /etc/vsftpd.conf
fi

# Remove FTP directory structure
sudo rm -rf /srv/ftp/

# Clear FTP logs (optional)
# sudo truncate -s 0 /var/log/vsftpd.log

echo "[+] FTP Anonymous Access scenario cleaned up!"
```

### Manual Cleanup Steps
1. Stop VSFTPd: `sudo systemctl stop vsftpd`
2. Restore configuration: `sudo mv /etc/vsftpd.conf.backup /etc/vsftpd.conf`
3. Remove FTP files: `sudo rm -rf /srv/ftp/`
4. Clear logs (optional): `sudo truncate -s 0 /var/log/vsftpd.log`

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_ftp_anonymous_access.sh

echo "[+] Resetting FTP Anonymous Access to basic state..."

# Run cleanup first
./cleanup.sh

# Wait for service to stop
sleep 2

# Run setup again
./setup.sh

echo "[+] FTP Anonymous Access scenario reset complete!"
```

## Investigation Opportunities

### For Blue Team Analysis
- FTP access pattern analysis
- Anonymous login monitoring
- File access auditing
- Data exfiltration detection
- Network file transfer analysis

### Learning Objectives
- FTP protocol security fundamentals
- Anonymous access risks
- File transfer monitoring
- Data loss prevention
- Legacy protocol security

## Security Notes
- Demonstrates common FTP misconfigurations
- Shows risks of anonymous access
- Should only be deployed in isolated lab environments
- Real systems should disable anonymous FTP access
- Use SFTP/FTPS for secure file transfers