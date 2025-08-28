#!/bin/bash
set -e

echo "=== Minecraft Server Setup Starting ==="

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
    openjdk-21-jre-headless \
    screen \
    wget

echo "Step 3: Creating minecraft server directory..."
mkdir -p /opt/minecraft-server
chown labadmin:labadmin /opt/minecraft-server

echo "Step 4: Downloading official Minecraft server..."
cd /opt/minecraft-server
# Download latest stable Minecraft server jar (1.21.8)
logger "MINECRAFT_SETUP: Downloading official Minecraft server jar"
wget -O server.jar "https://piston-data.mojang.com/v1/objects/6bce4ef400e4efaa63a13d5e6f6b500be969ef81/server.jar"
if [ $? -eq 0 ] && [ -f server.jar ] && [ -s server.jar ]; then
    logger "MINECRAFT_SETUP: Server jar downloaded successfully"
    chown labadmin:labadmin server.jar
    chmod 644 server.jar
else
    logger "MINECRAFT_SETUP: ERROR - Failed to download server jar"
    exit 1
fi

echo "Step 5: Accepting EULA and initial server setup..."
# Accept EULA automatically
logger "MINECRAFT_SETUP: Accepting Minecraft EULA"
echo "eula=true" > eula.txt
chown labadmin:labadmin eula.txt

echo "Step 6: Running initial server setup to generate files..."
logger "MINECRAFT_SETUP: Running initial server setup"
# Run server once to generate initial files (will exit after creating structure)
timeout 30 java -Xmx1G -Xms1G -jar server.jar nogui || true
logger "MINECRAFT_SETUP: Initial server files generated"

echo "Step 7: Configuring server properties..."
cat > server.properties << 'EOF'
# APTL Minecraft Server Configuration
server-port=25565
max-players=10
level-name=aptl-world
motd=APTL Purple Team Lab - Minecraft Server
difficulty=normal
gamemode=survival
online-mode=false
white-list=false
enable-command-block=true
spawn-protection=0
allow-flight=false
enable-rcon=false
broadcast-console-to-ops=true
view-distance=10
max-world-size=29999984
enable-status=true
enable-query=true
query.port=25565
EOF
chown -R labadmin:labadmin /opt/minecraft-server

echo "Step 8: Creating optimized startup script..."
cat > start-server.sh << 'EOF'
#!/bin/bash
cd /opt/minecraft-server

# Log startup to syslog for SIEM
logger "MINECRAFT_SERVER: Starting Minecraft server process"

# Launch server with optimized JVM parameters for container environment
java -Xmx2G -Xms1G \
     -XX:+UseG1GC \
     -XX:+ParallelRefProcEnabled \
     -XX:MaxGCPauseMillis=200 \
     -XX:+UnlockExperimentalVMOptions \
     -XX:+DisableExplicitGC \
     -XX:G1NewSizePercent=30 \
     -XX:G1MaxNewSizePercent=40 \
     -XX:G1HeapRegionSize=8M \
     -XX:G1ReservePercent=20 \
     -XX:G1HeapWastePercent=5 \
     -XX:G1MixedGCCountTarget=4 \
     -XX:InitiatingHeapOccupancyPercent=15 \
     -XX:G1MixedGCLiveThresholdPercent=90 \
     -XX:G1RSetUpdatingPauseTimePercent=5 \
     -XX:SurvivorRatio=32 \
     -XX:+PerfDisableSharedMem \
     -XX:MaxTenuringThreshold=1 \
     -jar server.jar nogui

# Log shutdown to syslog for SIEM
logger "MINECRAFT_SERVER: Minecraft server process stopped"
EOF

chmod +x start-server.sh
chown labadmin:labadmin start-server.sh
logger "MINECRAFT_SETUP: Startup script created"

echo "Step 9: Creating SIEM log processing script..."
cat > process-logs.sh << 'EOF'
#!/bin/bash

# Monitor Minecraft server logs and forward important events to syslog
if [ -f /opt/minecraft-server/logs/latest.log ]; then
    tail -F /opt/minecraft-server/logs/latest.log 2>/dev/null | while read line; do
        # Player login/logout events
        if echo "$line" | grep -q "joined the game\|left the game"; then
            logger -t MINECRAFT_PLAYER "$line"
        fi
        
        # Server start/stop events
        if echo "$line" | grep -q "Starting minecraft server\|Stopping server"; then
            logger -t MINECRAFT_SERVER "$line"
        fi
        
        # Command execution (admin activities)
        if echo "$line" | grep -q "\] \[Server thread/INFO\]: <"; then
            logger -t MINECRAFT_COMMAND "$line"
        fi
        
        # Error events
        if echo "$line" | grep -qE "ERROR|WARN|Exception"; then
            logger -t MINECRAFT_ERROR "$line"
        fi
    done &
fi
EOF

chmod +x process-logs.sh
chown labadmin:labadmin process-logs.sh
logger "MINECRAFT_SETUP: SIEM log processing script created"

echo "Step 10: Creating systemd service..."
cat > /etc/systemd/system/minecraft.service << 'EOF'
[Unit]
Description=Minecraft Server
After=network.target

[Service]
Type=forking
User=labadmin
WorkingDirectory=/opt/minecraft-server
ExecStart=/usr/bin/screen -dmS minecraft /opt/minecraft-server/start-server.sh
ExecStartPost=/bin/sleep 5
ExecStartPost=/opt/minecraft-server/process-logs.sh
ExecStop=/usr/bin/screen -S minecraft -X stuff "stop\n"
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable minecraft.service
logger "MINECRAFT_SETUP: Systemd service created and enabled"

echo "=== Minecraft Server Setup Complete ==="
echo "Server can be started with: systemctl start minecraft"
echo "Or manually with: /opt/minecraft-server/start-server.sh"

# Create flag to prevent re-running
mkdir -p /opt/lab
touch /opt/lab/.gameserver_installed