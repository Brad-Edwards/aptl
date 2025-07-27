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