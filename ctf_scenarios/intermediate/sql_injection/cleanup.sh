#!/bin/bash
# cleanup_sql_injection.sh

echo "[+] Cleaning up SQL Injection scenario..."

# Stop services
sudo systemctl stop apache2
sudo systemctl stop mysql

# Remove web application
sudo rm -rf /var/www/html/login/

# Remove database
sudo mysql -e "DROP DATABASE IF EXISTS ctf_db;"
sudo mysql -e "DROP USER IF EXISTS 'ctf_user'@'localhost';"

# Clear logs (optional)
# sudo truncate -s 0 /var/log/apache2/access.log
# sudo truncate -s 0 /var/log/mysql/error.log

echo "[+] SQL Injection scenario cleaned up!"