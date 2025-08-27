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

echo "Step 3: Installing VNC server for remote desktop access..."
apt-get install -y tigervnc-standalone-server

echo "Step 4: Configuring VNC for rdpuser..."
# Create VNC startup script for XFCE
mkdir -p /home/rdpuser/.vnc
cat > /home/rdpuser/.vnc/xstartup << 'EOF'
#!/bin/bash
[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources
export XKL_XMODMAP_DISABLE=1
exec startxfce4
EOF
chmod +x /home/rdpuser/.vnc/xstartup

# Set VNC password for rdpuser using vncpasswd
echo -e "vncpass123\nvncpass123\nn" | runuser -l rdpuser -c "vncpasswd" 2>/dev/null || true

chown -R rdpuser:rdpuser /home/rdpuser/.vnc

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

# Create minetest config directory for rdpuser
mkdir -p /home/rdpuser/.minetest
cat > /home/rdpuser/.minetest/minetest.conf << 'EOF'
# Default server connection
address = 172.20.0.21
port = 30000
name = rdpuser
# Disable sound for headless compatibility
enable_sound = false
EOF
chown -R rdpuser:rdpuser /home/rdpuser/.minetest

echo "Step 7: Starting VNC server for rdpuser..."
# Start VNC server on display :1 (port 5901) - allow external connections with higher resolution
su - rdpuser -c "vncserver :1 -geometry 1920x1080 -depth 24 -localhost no"

echo "=== Game Client Setup Complete ==="

# Create flag to prevent re-running
mkdir -p /opt/lab
touch /opt/lab/.gameclient_installed