#!/bin/bash
# Log everything for troubleshooting
exec > >(tee /var/log/user-data.log)
exec 2>&1

# Update system
echo "Updating Kali Linux system..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install additional useful tools for red team operations
echo "Installing additional tools..."
sudo apt-get install -y \
  git \
  python3-pip \
  golang \
  docker.io \
  docker-compose

# Enable Docker service
sudo systemctl enable docker
sudo systemctl start docker

# Add default user to docker group
sudo usermod -aG docker kali 2>/dev/null || true

# Create working directory for red team operations
mkdir -p /home/kali/operations

# Create a welcome script with lab information
cat > /home/kali/lab_info.sh << 'EOFSCRIPT'
#!/bin/bash
echo "=== APTL Red Team Kali Instance ==="
echo ""
echo "Lab Network Information:"
%{ if siem_private_ip != "" ~}
echo "  SIEM Private IP: ${siem_private_ip}"
%{ else ~}
echo "  SIEM Private IP: Not available (SIEM disabled)"
%{ endif ~}
%{ if victim_private_ip != "" ~}
echo "  Victim Private IP: ${victim_private_ip}"
%{ else ~}
echo "  Victim Private IP: Not available (Victim disabled)"
%{ endif ~}
echo "  Kali Private IP: $(hostname -I | awk '{print $1}')"
echo ""
echo "Available Tools:"
echo "  - Metasploit Framework"
echo "  - Nmap"
echo "  - Burp Suite"
echo "  - SQLMap"
echo "  - John the Ripper"
echo "  - Hashcat"
echo "  - Hydra"
echo "  - And many more..."
echo ""
echo "Working Directory: ~/operations"
echo ""
echo "Happy hunting!"
EOFSCRIPT
chmod +x /home/kali/lab_info.sh

# Set proper ownership
chown -R kali:kali /home/kali/operations 2>/dev/null || true
chown kali:kali /home/kali/lab_info.sh 2>/dev/null || true

echo "Kali Linux red team instance setup complete" 