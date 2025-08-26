#!/bin/bash
set -e

echo "=== Game Server Setup Starting ==="

# Check if already installed
if [ -f /opt/minetest/.gameserver_installed ]; then
    echo "Game server already installed, exiting..."
    exit 0
fi

echo "Step 1: Enabling repositories and installing Minetest server..."
# Enable CRB repository for Rocky Linux 9
dnf config-manager --set-enabled crb || dnf config-manager --set-enabled powertools || true
# Install EPEL if not already present
dnf install -y epel-release || true
# Install minetest-server package
dnf install -y minetest-server

echo "Step 2: Creating minetest server directories..."
mkdir -p /opt/minetest/{worlds,games,mods}
mkdir -p /home/labadmin/.minetest

echo "Step 3: Configuring minetest server..."
# Create server configuration
cat > /opt/minetest/minetest.conf << 'EOF'
# Minetest Server Configuration for GameConqueror Demo

# Server settings
server_name = APTL Minetest Demo Server
server_description = Purple Team Lab Minetest Server for Memory Scanning Demo
motd = Welcome to the APTL GameConqueror Demo!
max_users = 10
port = 30000
bind_address = 0.0.0.0

# World settings
default_game = minetest_game

# Security settings
enable_client_modding = false
csm_restriction_flags = 62
csm_restriction_noderange = 0

# Debug and logging
debug_log_level = action
server_side_occlusion_culling = true

# Performance
dedicated_server_step = 0.09
active_object_send_range_blocks = 3
active_block_range = 2
max_block_send_distance = 6
max_block_generate_distance = 6

# Player settings
static_spawnpoint = 0,10,0
enable_damage = true
enable_pvp = false
creative_mode = false
enable_flying = false

# Chat settings
strip_color_codes = false
chat_message_limit_per_10sec = 10
chat_message_limit_trigger_kick = 50
EOF

echo "Step 4: Creating world and setting permissions..."
# Create world directory
mkdir -p /opt/minetest/worlds/demo_world
cat > /opt/minetest/worlds/demo_world/world.mt << 'EOF'
gameid = minetest_game
world_name = demo_world
enable_damage = true
creative_mode = false
EOF

# Set proper ownership
chown -R labadmin:labadmin /opt/minetest
chown -R labadmin:labadmin /home/labadmin/.minetest

echo "Step 5: Creating systemd service for minetest server..."
cat > /etc/systemd/system/minetest-server.service << 'EOF'
[Unit]
Description=Minetest Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=labadmin
Group=labadmin
WorkingDirectory=/opt/minetest
ExecStart=/usr/bin/minetestserver --config /opt/minetest/minetest.conf --worldname demo_world --logfile /opt/minetest/server.log
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "Step 6: Enabling and starting minetest server..."
systemctl daemon-reload
systemctl enable minetest-server.service
systemctl start minetest-server.service

echo "Step 7: Verifying server startup..."
sleep 5
if systemctl is-active --quiet minetest-server.service; then
    echo "Minetest server started successfully"
    systemctl status minetest-server.service --no-pager -l
else
    echo "Warning: Minetest server may not have started properly"
    systemctl status minetest-server.service --no-pager -l
    journalctl -u minetest-server.service --no-pager -l
fi

echo "=== Game Server Setup Complete ==="

# Create flag to prevent re-running
mkdir -p /opt/minetest
touch /opt/minetest/.gameserver_installed

echo "Server is running on port 30000"
echo "Logs available at: /opt/minetest/server.log"
echo "World data at: /opt/minetest/worlds/demo_world"