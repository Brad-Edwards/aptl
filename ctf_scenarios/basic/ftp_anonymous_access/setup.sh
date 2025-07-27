#!/bin/bash
# setup_ftp_anonymous_access.sh

echo "[+] Setting up FTP Anonymous Access scenario..."

# Install VSFTPd if not present
sudo apt-get update -qq
sudo apt-get install -y vsftpd

# Create FTP directory structure
sudo mkdir -p /srv/ftp/public
sudo mkdir -p /srv/ftp/uploads
sudo mkdir -p /srv/ftp/backups
sudo mkdir -p /srv/ftp/documents

# Create flag files
echo "APTL{ftp_4n0nym0us_4cc3ss}" | sudo tee /srv/ftp/public/flag.txt > /dev/null
echo "APTL{d4t4_3xf1ltr4t10n_m4st3r}" | sudo tee /srv/ftp/backups/hidden_flag.txt > /dev/null

# Create decoy files
echo "Welcome to the company FTP server!" | sudo tee /srv/ftp/public/welcome.txt > /dev/null
echo "Employee handbook and policies" | sudo tee /srv/ftp/documents/handbook.pdf > /dev/null
echo "System backup from $(date)" | sudo tee /srv/ftp/backups/system_backup.log > /dev/null
echo "Temporary upload directory" | sudo tee /srv/ftp/uploads/readme.txt > /dev/null

# Create interesting files that hint at other systems
cat << 'EOF' | sudo tee /srv/ftp/documents/network_info.txt > /dev/null
Company Network Information
===========================
Web Server: 192.168.1.10
Database Server: 192.168.1.20  
File Server: 192.168.1.30 (you are here)
Mail Server: 192.168.1.40

FTP Access:
- Public files available via anonymous login
- Employee files require authentication
EOF

# Configure VSFTPd for anonymous access
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.backup
cat << 'EOF' | sudo tee /etc/vsftpd.conf > /dev/null
# VSFTPd Configuration for CTF Scenario
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=NO
write_enable=NO
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

# Anonymous access configuration
anon_root=/srv/ftp
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO
no_anon_password=YES
anon_world_readable_only=YES

# Directory listing
ls_recurse_enable=YES
hide_ids=NO
EOF

# Set proper permissions
sudo chown -R ftp:ftp /srv/ftp/
sudo chmod -R 755 /srv/ftp/
sudo chmod 644 /srv/ftp/public/flag.txt
sudo chmod 644 /srv/ftp/backups/hidden_flag.txt

# Start FTP service
sudo systemctl start vsftpd
sudo systemctl enable vsftpd

echo "[+] FTP Anonymous Access scenario deployed!"
echo "[+] Target: FTP service on port 21"
echo "[+] Access: anonymous login (no password)"
echo "[+] Flags: /public/flag.txt, /backups/hidden_flag.txt"
echo "[+] Test: ftp localhost"