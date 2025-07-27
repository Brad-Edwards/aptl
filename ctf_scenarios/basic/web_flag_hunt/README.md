# Basic CTF Scenario 1: Web Flag Hunt

## Overview
Simple web-based flag discovery scenario involving basic directory traversal and file enumeration. Perfect for red team agents to practice reconnaissance and basic web exploitation.

## Scenario Details
- **Difficulty**: Basic
- **Attack Vectors**: Directory traversal, file enumeration, web reconnaissance
- **Skills Tested**: Basic web scanning, manual exploration
- **Expected Time**: 10-15 minutes

## Setup

### Prerequisites
- Apache2 web server
- Basic HTML/text files

### Setup Script
```bash
#!/bin/bash
# setup_web_flag_hunt.sh

echo "[+] Setting up Web Flag Hunt scenario..."

# Install Apache2 if not present
sudo apt-get update -qq
sudo apt-get install -y apache2

# Create web directory structure
sudo mkdir -p /var/www/html/admin
sudo mkdir -p /var/www/html/backup
sudo mkdir -p /var/www/html/temp
sudo mkdir -p /var/www/html/.hidden

# Create flag file
echo "APTL{w3b_3num3r4t10n_m4st3r}" | sudo tee /var/www/html/.hidden/flag.txt > /dev/null

# Create decoy files
echo "Welcome to the company website!" | sudo tee /var/www/html/index.html > /dev/null
echo "Admin panel coming soon..." | sudo tee /var/www/html/admin/index.html > /dev/null
echo "Backup files stored here" | sudo tee /var/www/html/backup/readme.txt > /dev/null
echo "Temporary files directory" | sudo tee /var/www/html/temp/info.txt > /dev/null

# Create robots.txt with hints
cat << 'EOF' | sudo tee /var/www/html/robots.txt > /dev/null
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /.hidden/
EOF

# Create .htaccess to allow directory listings
echo "Options +Indexes" | sudo tee /var/www/html/.htaccess > /dev/null

# Start Apache2
sudo systemctl start apache2
sudo systemctl enable apache2

# Set permissions
sudo chown -R www-data:www-data /var/www/html/
sudo chmod -R 755 /var/www/html/

echo "[+] Web Flag Hunt scenario deployed!"
echo "[+] Target: http://localhost/"
echo "[+] Flag location: /.hidden/flag.txt"
echo "[+] Hint: Check robots.txt for disallowed directories"
```

### Manual Setup Steps
1. Install Apache2: `sudo apt-get install apache2`
2. Create directory structure in `/var/www/html/`
3. Place flag in `/.hidden/flag.txt`
4. Create robots.txt with directory hints
5. Start Apache2 service

## Attack Methodology

### Expected Attack Path
1. **Reconnaissance**: Port scan discovers HTTP service
2. **Web Enumeration**: 
   - Directory scanning with dirb/gobuster
   - robots.txt discovery
   - Manual directory browsing
3. **Flag Discovery**: Access hidden directory and retrieve flag

### Key Commands Red Team Will Use
```bash
# Port scanning
nmap -sV <target_ip>

# Directory enumeration
dirb http://<target_ip>/
gobuster dir -u http://<target_ip>/ -w /usr/share/wordlists/dirb/common.txt

# Manual exploration
curl http://<target_ip>/robots.txt
curl http://<target_ip>/.hidden/flag.txt
```

## Blue Team Detection Signatures

### Log Patterns to Monitor
```
# Apache access logs (/var/log/apache2/access.log)
- Multiple 404 errors in sequence (directory scanning)
- Access to robots.txt
- Access to /.hidden/ directory
- Automated user agents (dirb, gobuster, nikto)
```

### Detection Rules
```
# High volume of 404s
GET requests with 404 response > 50 in 5 minutes

# Robots.txt access
GET /robots.txt

# Hidden directory access
GET /.hidden/*

# Directory scanning tools
User-Agent contains: dirb, gobuster, nikto, dirbuster
```

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_web_flag_hunt.sh

echo "[+] Cleaning up Web Flag Hunt scenario..."

# Stop Apache2
sudo systemctl stop apache2
sudo systemctl disable apache2

# Remove web files
sudo rm -rf /var/www/html/.hidden/
sudo rm -f /var/www/html/robots.txt
sudo rm -f /var/www/html/.htaccess
sudo rm -rf /var/www/html/admin/
sudo rm -rf /var/www/html/backup/
sudo rm -rf /var/www/html/temp/

# Restore default Apache page
sudo rm -f /var/www/html/index.html

echo "[+] Web Flag Hunt scenario cleaned up!"
```

### Manual Cleanup Steps
1. Stop Apache2: `sudo systemctl stop apache2`
2. Remove created directories and files
3. Clear Apache access logs: `sudo truncate -s 0 /var/log/apache2/access.log`

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_web_flag_hunt.sh

echo "[+] Resetting Web Flag Hunt to basic state..."

# Run cleanup first
./cleanup_web_flag_hunt.sh

# Wait a moment
sleep 2

# Run setup again
./setup_web_flag_hunt.sh

echo "[+] Web Flag Hunt scenario reset complete!"
```

## Investigation Opportunities

### For Blue Team Analysis
- Web server access patterns
- Directory enumeration detection
- Automated tool identification
- Timeline reconstruction from logs
- Baseline vs. attack traffic comparison

### Learning Objectives
- Understanding web reconnaissance techniques
- Log analysis fundamentals
- Pattern recognition in HTTP traffic
- Introduction to web application security monitoring