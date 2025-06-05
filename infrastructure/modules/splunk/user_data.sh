#!/bin/bash
# SPDX-License-Identifier: BUSL-1.1

# Log everything for troubleshooting
exec > >(tee /var/log/user-data.log)
exec 2>&1

# Update system
sudo dnf update -y

# Install required packages
sudo dnf install -y wget curl

# Set hostname
sudo hostnamectl set-hostname splunk.local

# Add hostname to /etc/hosts using private IP
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
echo "$PRIVATE_IP splunk.local" | sudo tee -a /etc/hosts

# Create Splunk installation script
cat > /home/ec2-user/install_splunk.sh << 'EOFSCRIPT'
#!/bin/bash

echo "Splunk Enterprise Installation Script"
echo "===================================="

# Check if Splunk is already installed
if [ -d "/opt/splunk" ]; then
    echo "Splunk appears to already be installed in /opt/splunk"
    echo "Current status:"
    sudo /opt/splunk/bin/splunk status
    exit 0
fi

# Download Splunk Enterprise
echo "Downloading Splunk Enterprise..."
cd /tmp
wget -O splunk-enterprise.rpm "https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-b6b9c8185839-linux-2.6-x86_64.rpm"

if [ $? -ne 0 ]; then
    echo "Failed to download Splunk. Please check your internet connection."
    exit 1
fi

echo "Installing Splunk Enterprise..."
sudo rpm -ivh splunk-enterprise.rpm

# Create splunk user and set ownership
sudo groupadd splunk 2>/dev/null || true
sudo useradd -g splunk -d /opt/splunk -s /bin/bash splunk 2>/dev/null || true
sudo chown -R splunk:splunk /opt/splunk

echo ""
echo "Splunk has been downloaded and installed to /opt/splunk"
echo ""
echo "To complete the setup:"
echo "1. Start Splunk: sudo -u splunk /opt/splunk/bin/splunk start --accept-license"
echo "2. Set admin password when prompted"
echo "3. Access web interface: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
echo ""
read -p "Would you like to start Splunk now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting Splunk..."
    sudo -u splunk /opt/splunk/bin/splunk start --accept-license
    
    echo ""
    echo "Splunk is now running!"
    echo "Web interface: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
    echo "Default login: admin / (password you just set)"
    echo ""
    echo "To configure log forwarding reception:"
    echo "sudo -u splunk /opt/splunk/bin/splunk enable listen 9997"
    echo ""
else
    echo "You can start Splunk later with:"
    echo "sudo -u splunk /opt/splunk/bin/splunk start --accept-license"
fi
EOFSCRIPT

chmod +x /home/ec2-user/install_splunk.sh

# Create a simple status check script
cat > /home/ec2-user/check_splunk.sh << 'EOFSCRIPT'
#!/bin/bash
echo "Splunk Status Check"
echo "=================="

if [ -d "/opt/splunk" ]; then
    echo "Splunk installation: Found"
    echo "Splunk status:"
    sudo /opt/splunk/bin/splunk status 2>/dev/null || echo "Splunk not running"
    
    echo ""
    echo "To start Splunk: sudo -u splunk /opt/splunk/bin/splunk start"
    echo "To stop Splunk: sudo -u splunk /opt/splunk/bin/splunk stop"
    echo "Web interface: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
else
    echo "Splunk not installed. Run: ./install_splunk.sh"
fi
EOFSCRIPT

chmod +x /home/ec2-user/check_splunk.sh

echo "Splunk SIEM instance setup complete."
echo "Run ./install_splunk.sh to download and install Splunk Enterprise" 