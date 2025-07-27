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