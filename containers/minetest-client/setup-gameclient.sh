#!/bin/bash
set -e

echo "=== Game Client Setup Starting ==="

# Check if already installed
if [ -f /opt/lab/.gameclient_installed ]; then
    echo "Game client already installed, exiting..."
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive

echo "Step 1: Updating package lists..."
apt-get update

echo "Step 2: Installing XFCE desktop environment..."
apt-get install -y \
    xfce4 \
    xfce4-goodies \
    xfce4-terminal

echo "Step 3: Installing XRDP for remote desktop access..."
apt-get install -y xrdp

echo "Step 4: Configuring XRDP..."
# Configure XRDP to use XFCE session
echo "xfce4-session" > /etc/skel/.xsession
echo "xfce4-session" > /root/.xsession

# Create .xsession for labadmin user
mkdir -p /home/labadmin
echo "xfce4-session" > /home/labadmin/.xsession
chown labadmin:labadmin /home/labadmin/.xsession

# Configure XRDP policy
echo "allowed_users=anybody" >> /etc/X11/Xwrapper.config

echo "Step 5: Installing Minetest client and GameConqueror..."
apt-get install -y \
    minetest \
    gameconqueror

echo "Step 6: Configuring Minetest client..."
# Create minetest config directory for labadmin
mkdir -p /home/labadmin/.minetest
cat > /home/labadmin/.minetest/minetest.conf << 'EOF'
# Default server connection
address = 172.20.0.21
port = 30000
name = labuser
# Disable sound for headless compatibility
enable_sound = false
EOF
chown -R labadmin:labadmin /home/labadmin/.minetest

echo "Step 7: Enabling XRDP service..."
systemctl enable xrdp

echo "=== Game Client Setup Complete ==="

# Create flag to prevent re-running
mkdir -p /opt/lab
touch /opt/lab/.gameclient_installed