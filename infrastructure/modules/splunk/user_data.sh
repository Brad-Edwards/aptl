#!/bin/bash
# SPDX-License-Identifier: BUSL-1.1

# Log everything for troubleshooting
exec > >(tee /var/log/user-data.log)
exec 2>&1

# Update system
sudo dnf update -y

# Install required packages
sudo dnf install -y wget curl policycoreutils-python-utils

# Set hostname
sudo hostnamectl set-hostname splunk.local

# Add hostname to /etc/hosts using private IP
PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
echo "$PRIVATE_IP splunk.local" | sudo tee -a /etc/hosts

# Configure SELinux for Splunk operation
echo "Configuring SELinux for Splunk..."

# Set SELinux to permissive mode to allow Splunk to bind to port 5514
sudo setenforce 0 || true
sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config

# Add custom SELinux ports for Splunk syslog reception
sudo semanage port -a -t syslogd_port_t -p udp 5514 2>/dev/null || true
sudo semanage port -a -t syslogd_port_t -p tcp 5514 2>/dev/null || true

# Allow Splunk to bind to non-standard ports
sudo setsebool -P httpd_can_network_connect 1 || true

# Create Splunk configuration files in /tmp (will be moved after installation)

# Create indexes.conf - defines the red team index
cat > /tmp/indexes.conf << 'EOF'
[keplerops-aptl-redteam]
homePath = $SPLUNK_DB/keplerops-aptl-redteam/db
coldPath = $SPLUNK_DB/keplerops-aptl-redteam/colddb
thawedPath = $SPLUNK_DB/keplerops-aptl-redteam/thaweddb
maxDataSize = auto_high_volume
maxHotBuckets = 10
maxWarmDBCount = 300
EOF

# Create inputs.conf - configures syslog inputs with index routing
cat > /tmp/inputs.conf << 'EOF'
[udp://5514]
sourcetype = syslog
index = main

[tcp://5514] 
sourcetype = syslog
index = main
EOF

# Create props.conf - defines source types for red team activities  
cat > /tmp/props.conf << 'EOF'
[redteam:commands]
KV_MODE = none
EXTRACT-command = (?<command>.*)
TIME_PREFIX = ^\w+\s+\d+\s+\d+:\d+:\d+
category = Custom
description = Red team command execution logs

[redteam:network]
KV_MODE = none
TIME_PREFIX = ^\w+\s+\d+\s+\d+:\d+:\d+
category = Custom
description = Red team network activity logs

[redteam:auth]
KV_MODE = none
TIME_PREFIX = ^\w+\s+\d+\s+\d+:\d+:\d+
category = Custom  
description = Red team authentication logs
EOF

# Create transforms.conf - routes red team logs to correct index
cat > /tmp/transforms.conf << 'EOF'
[redteam_routing]
REGEX = REDTEAM_LOG
DEST_KEY = _MetaData:Index
FORMAT = keplerops-aptl-redteam
EOF

# Config files remain in /tmp for manual installation after Splunk is installed
# They will be moved by the install script after Splunk is properly installed

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
wget -O splunk-enterprise.rpm "https://download.splunk.com/products/splunk/releases/9.4.2/linux/splunk-9.4.2-e9664af3d956.x86_64.rpm"

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

# Move pre-configured files to Splunk config directory
if [ -f "/tmp/indexes.conf" ]; then
    sudo mv /tmp/indexes.conf /opt/splunk/etc/system/local/
    sudo mv /tmp/inputs.conf /opt/splunk/etc/system/local/
    sudo mv /tmp/props.conf /opt/splunk/etc/system/local/
    sudo mv /tmp/transforms.conf /opt/splunk/etc/system/local/
    sudo chown splunk:splunk /opt/splunk/etc/system/local/*.conf
    echo "Pre-configured red team logging configuration installed"
fi

echo ""
echo "Splunk has been downloaded and installed to /opt/splunk"
echo ""
echo "To complete the setup:"
echo "1. Start Splunk: sudo -u splunk /opt/splunk/bin/splunk start --accept-license"
echo "2. Set admin password when prompted"
echo "3. Access web interface: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
echo ""
read -p "Would you like to start Splunk now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting Splunk..."
    sudo -u splunk /opt/splunk/bin/splunk start --accept-license
    
    echo ""
    echo "⚠️  IMPORTANT: Please set a secure admin password when prompted above!"
    echo ""
    echo "After Splunk starts, configure UDP syslog input manually:"
    echo "1. Login to web interface: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
    echo "2. Go to Settings > Data Inputs > UDP"
    echo "3. Add new UDP input on port 5514, source type = syslog"
    echo ""
    echo "Or use CLI (replace 'yourpassword' with your actual password):"
    echo "sudo -u splunk /opt/splunk/bin/splunk add udp 5514 -sourcetype syslog -auth admin:yourpassword"
    echo ""
    echo "🔒 For security, no default credentials are configured automatically."
    echo ""
else
    echo "You can start Splunk later with:"
    echo "sudo -u splunk /opt/splunk/bin/splunk start --accept-license"
    echo ""
    echo "After starting, configure UDP input with:"
    echo "sudo -u splunk /opt/splunk/bin/splunk add udp 5514 -sourcetype syslog -auth admin:yourpassword"
fi
EOFSCRIPT

chmod +x /home/ec2-user/install_splunk.sh

# Create log input configuration script
cat > /home/ec2-user/configure_splunk_inputs.sh << 'EOFSCRIPT'
#!/bin/bash
echo "Splunk Log Input Configuration"
echo "=============================="

if [ ! -d "/opt/splunk" ]; then
    echo "❌ Splunk not installed. Run ./install_splunk.sh first."
    exit 1
fi

# Check if Splunk is running
if ! sudo -u splunk /opt/splunk/bin/splunk status >/dev/null 2>&1; then
    echo "❌ Splunk is not running. Start it first:"
    echo "sudo -u splunk /opt/splunk/bin/splunk start"
    exit 1
fi

# Check if inputs already exist
UDP_EXISTS=$(sudo -u splunk /opt/splunk/bin/splunk list udp 2>/dev/null | grep -q "5514" && echo "yes" || echo "no")
TCP_EXISTS=$(sudo -u splunk /opt/splunk/bin/splunk list tcp 2>/dev/null | grep -q "5514" && echo "yes" || echo "no")

if [ "$UDP_EXISTS" = "yes" ] && [ "$TCP_EXISTS" = "yes" ]; then
    echo "✅ Both UDP and TCP inputs on port 5514 already configured"
    exit 0
fi

echo "Configuring syslog inputs on port 5514 (UDP + TCP)..."
echo "Please enter your Splunk admin password:"
read -s -p "Password: " PASSWORD
echo ""

SUCCESS=true

# Configure UDP input if not exists
if [ "$UDP_EXISTS" = "no" ]; then
    echo "Configuring UDP 5514..."
    if sudo -u splunk /opt/splunk/bin/splunk add udp 5514 -sourcetype syslog -auth admin:"$PASSWORD" >/dev/null 2>&1; then
        echo "✅ UDP syslog input configured on port 5514"
    else
        echo "❌ Failed to configure UDP input"
        SUCCESS=false
    fi
else
    echo "✅ UDP input on port 5514 already exists"
fi

# Configure TCP input if not exists
if [ "$TCP_EXISTS" = "no" ]; then
    echo "Configuring TCP 5514..."
    if sudo -u splunk /opt/splunk/bin/splunk add tcp 5514 -sourcetype syslog -auth admin:"$PASSWORD" >/dev/null 2>&1; then
        echo "✅ TCP syslog input configured on port 5514"
    else
        echo "❌ Failed to configure TCP input"
        SUCCESS=false
    fi
else
    echo "✅ TCP input on port 5514 already exists"
fi

if [ "$SUCCESS" = "true" ]; then
    echo ""
    echo "🔗 Splunk is now ready to receive logs from victim and Kali machines"
    echo "📊 View logs: Search & Reporting > index=main"
else
    echo ""
    echo "❌ Some configurations failed. Please check your password and try again."
    echo "Or configure manually via web interface:"
    echo "1. Go to Settings > Data Inputs > TCP"
    echo "2. Add new TCP input on port 5514, source type = syslog"
    echo "3. Go to Settings > Data Inputs > UDP" 
    echo "4. Add new UDP input on port 5514, source type = syslog"
fi
EOFSCRIPT

chmod +x /home/ec2-user/configure_splunk_inputs.sh

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
    echo "Web interface: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
else
    echo "Splunk not installed. Run: ./install_splunk.sh"
fi
EOFSCRIPT

chmod +x /home/ec2-user/check_splunk.sh

echo "Splunk SIEM instance setup complete."
echo "Run ./install_splunk.sh to download and install Splunk Enterprise" 