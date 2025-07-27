#!/bin/bash
# cleanup_cross_site_scripting.sh

echo "[+] Cleaning up Cross-Site Scripting scenario..."

sudo rm -rf /var/www/html/xss
sudo systemctl stop apache2
sudo systemctl disable apache2

echo "[+] Cross-Site Scripting scenario cleaned up!"
