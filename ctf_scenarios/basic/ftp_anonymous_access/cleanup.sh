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