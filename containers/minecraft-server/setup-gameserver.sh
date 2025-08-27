#!/bin/bash
set -e

echo "=== Minecraft Server Setup Starting ===

# Check if already installed
if [ -f /opt/lab/.gameserver_installed ]; then
    echo "Minecraft server already installed, exiting..."
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive

echo "Step 1: Updating package lists..."
apt-get update

echo "Step 2: Installing Java Runtime Environment..."
apt-get install -y \
    openjdk-17-jre-headless \
    screen

echo "Step 3: Creating minecraft server directory..."
mkdir -p /opt/minecraft-server
chown labadmin:labadmin /opt/minecraft-server

echo "Step 4: Preparing for Minecraft server installation..."
# Note: Actual Minecraft server installation will be done manually
# This just sets up the environment

echo "Step 5: Creating server configuration directories..."
# Create minecraft configuration directory
mkdir -p /opt/minecraft-server/config
cat > /opt/minecraft-server/server.properties << 'EOF'
# Minecraft Server Properties
server-port=25565
max-players=20
level-name=world
motd=APTL Minecraft Server - Purple Team Lab
difficulty=normal
gamemode=survival
online-mode=false
white-list=false
EOF
chown -R labadmin:labadmin /opt/minecraft-server

echo "Step 6: Setting up Minecraft server service..."
# The server will be started manually by the user
echo "Minecraft server environment ready. Server jar should be installed manually."

echo "=== Minecraft Server Setup Complete ===

# Create flag to prevent re-running
mkdir -p /opt/lab
touch /opt/lab/.gameserver_installed