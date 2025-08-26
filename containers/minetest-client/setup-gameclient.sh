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

echo "Step 2: Installing basic packages for now..."
apt-get install -y \
    minetest \
    gameconqueror

echo "=== Game Client Setup Complete (Basic) ==="

echo "Minetest and GameConqueror installed successfully"
echo "GUI components will be added in next phase"

# Create flag to prevent re-running
mkdir -p /opt/lab
touch /opt/lab/.gameclient_installed