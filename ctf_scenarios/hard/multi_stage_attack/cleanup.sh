#!/bin/bash
# cleanup_multi_stage_attack.sh

echo "[+] Cleaning up Multi-Stage Attack scenario..."

# Stop services
sudo systemctl stop apache2 mysql ssh smbd nmbd nfs-kernel-server

# Remove users
sudo userdel -r jsmith 2>/dev/null
sudo userdel -r mjones 2>/dev/null
sudo userdel -r bwilson 2>/dev/null
sudo userdel -r fileserver 2>/dev/null

# Remove web application
sudo rm -rf /var/www/html/portal/

# Remove database
sudo mysql -e "DROP DATABASE IF EXISTS company_db;"
sudo mysql -e "DROP USER IF EXISTS 'web_user'@'localhost';"

# Remove file shares
sudo umount /srv/nfs/shared 2>/dev/null
sudo rm -rf /srv/nfs/
sudo rm -rf /srv/samba/

# Restore configurations
sudo sed -i '/\/srv\/nfs/d' /etc/exports
sudo sed -i '/\[shared\]/,$d' /etc/samba/smb.conf

# Remove sudo entries
sudo sed -i '/jsmith ALL=(ALL) NOPASSWD:/d' /etc/sudoers
sudo sed -i '/mjones ALL=(ALL) NOPASSWD:/d' /etc/sudoers

# Remove SUID binary
sudo rm -f /usr/local/bin/file_backup

# Remove cron job
sudo rm -f /etc/cron.d/system_update

# Remove flags and temp files
sudo rm -f /root/final_flag.txt
sudo rm -f /tmp/.persistence

# Restart services with clean config
sudo systemctl restart smbd nmbd nfs-kernel-server

echo "[+] Multi-Stage Attack scenario cleaned up!"