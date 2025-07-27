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