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