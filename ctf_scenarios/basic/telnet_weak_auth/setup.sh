#!/bin/bash
# setup_telnet_weak_auth.sh

echo "[+] Setting up Telnet Weak Authentication scenario..."

# Install telnet server
sudo apt-get update -qq
sudo apt-get install -y telnetd xinetd

# Create telnet user accounts with weak passwords
sudo useradd -m -s /bin/bash admin
sudo useradd -m -s /bin/bash guest
sudo useradd -m -s /bin/bash operator
sudo useradd -m -s /bin/bash service

echo "admin:admin" | sudo chpasswd
echo "guest:guest" | sudo chpasswd
echo "operator:password" | sudo chpasswd
echo "service:service123" | sudo chpasswd

# Create flag files
echo "APTL{t3ln3t_w34k_4uth}" | sudo tee /home/admin/flag.txt > /dev/null
echo "APTL{cl34r_t3xt_pr0t0c0l}" | sudo tee /home/operator/system_flag.txt > /dev/null

# Create interesting files
cat << 'EOF' | sudo tee /home/admin/system_info.txt > /dev/null
System Administration Notes
===========================
Default Accounts:
- admin/admin (system administrator)
- guest/guest (guest access)
- operator/password (system operator)
- service/service123 (service account)

Security Note: This system uses legacy telnet for remote access.
Consider upgrading to SSH for encrypted communications.
EOF

echo "System backup and maintenance logs" | sudo tee /home/operator/backup_logs.txt > /dev/null
echo "Guest user welcome information" | sudo tee /home/guest/welcome.txt > /dev/null

# Configure xinetd for telnet
cat << 'EOF' | sudo tee /etc/xinetd.d/telnet > /dev/null
service telnet
{
    disable = no
    flags = REUSE
    socket_type = stream
    wait = no
    user = root
    server = /usr/sbin/in.telnetd
    log_on_failure += USERID
    bind = 0.0.0.0
}
EOF

# Create custom banner
cat << 'EOF' | sudo tee /etc/issue.net > /dev/null
================================================================
    CORPORATE NETWORK SYSTEM - AUTHORIZED ACCESS ONLY
================================================================
Welcome to the Corporate Legacy System (CLS-2019)
System Type: Production Server
Location: Data Center Alpha

WARNING: This system is for authorized users only.
All activities are monitored and logged.

For technical support, contact: support@company.local
Default credentials should be changed after first login.

================================================================
EOF

# Configure telnet to use custom banner
echo 'BANNER_FILE="/etc/issue.net"' | sudo tee -a /etc/default/telnetd > /dev/null

# Set file permissions
sudo chown admin:admin /home/admin/flag.txt
sudo chmod 600 /home/admin/flag.txt
sudo chown operator:operator /home/operator/system_flag.txt
sudo chmod 600 /home/operator/system_flag.txt

# Start services
sudo systemctl restart xinetd
sudo systemctl enable xinetd

# Ensure telnet port is open
sudo ufw allow 23/tcp 2>/dev/null || true

echo "[+] Telnet Weak Authentication scenario deployed!"
echo "[+] Target: Telnet service on port 23"
echo "[+] Test accounts:"
echo "    admin/admin (flag in ~/flag.txt)"
echo "    guest/guest (basic access)"
echo "    operator/password (flag in ~/system_flag.txt)"
echo "    service/service123 (service account)"
echo "[+] Test: telnet localhost"