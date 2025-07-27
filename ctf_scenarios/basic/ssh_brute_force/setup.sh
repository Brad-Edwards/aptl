#!/bin/bash
# setup_ssh_brute_force.sh

echo "[+] Setting up SSH Brute Force scenario..."

# Install SSH if not present
sudo apt-get update -qq
sudo apt-get install -y openssh-server

# Create vulnerable user account
sudo useradd -m -s /bin/bash ctfuser
echo "ctfuser:password123" | sudo chpasswd

# Create flag file in user's home
echo "APTL{ssh_brut3_f0rc3_succ3ss}" | sudo tee /home/ctfuser/flag.txt > /dev/null
sudo chown ctfuser:ctfuser /home/ctfuser/flag.txt
sudo chmod 600 /home/ctfuser/flag.txt

# Configure SSH for the scenario
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Allow password authentication and create permissive config
cat << 'EOF' | sudo tee -a /etc/ssh/sshd_config > /dev/null

# CTF Scenario Configuration
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin no
MaxAuthTries 10
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Start SSH service
sudo systemctl start ssh
sudo systemctl enable ssh

# Add some decoy users with stronger passwords
sudo useradd -m -s /bin/bash admin
echo "admin:$(openssl rand -base64 32)" | sudo chpasswd

sudo useradd -m -s /bin/bash backup
echo "backup:$(openssl rand -base64 32)" | sudo chpasswd

echo "[+] SSH Brute Force scenario deployed!"
echo "[+] Target: SSH service on port 22"
echo "[+] Vulnerable user: ctfuser"
echo "[+] Password: password123"
echo "[+] Flag location: /home/ctfuser/flag.txt"