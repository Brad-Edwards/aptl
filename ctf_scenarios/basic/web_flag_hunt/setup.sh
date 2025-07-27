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