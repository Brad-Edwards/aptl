#!/bin/bash

# Cleanup script for basic CTF scenario

# Parse SSH connection details from lab_connections.txt
LAB_CONNECTIONS="${LAB_CONNECTIONS:-../../../lab_connections.txt}"

if [ ! -f "$LAB_CONNECTIONS" ]; then
    echo "Error: lab_connections.txt not found at $LAB_CONNECTIONS"
    exit 1
fi

# Extract SSH details for victim
SSH_KEY=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*-i \([^ ]*\).*/\1/p' | head -1)
SSH_USER=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*ssh -i [^ ]* \([^@]*\)@.*/\1/p' | head -1)
SSH_HOST=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*@\([^ ]*\).*/\1/p' | head -1)
SSH_PORT=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*-p \([0-9]*\).*/\1/p' | head -1)

# Expand tilde in SSH_KEY path
SSH_KEY="${SSH_KEY/#\~/$HOME}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

echo "Cleaning up victim container..."

ssh $SSH_OPTS -p "$SSH_PORT" -i "$SSH_KEY" "$SSH_USER@$SSH_HOST" "
    sudo rm -f /usr/local/bin/backup /tmp/backup_util /tmp/vulnerable_app.py /tmp/victim_setup.sh
    sudo rm -f /root/flag.txt
    sudo systemctl stop ctf-web 2>/dev/null
    sudo systemctl disable ctf-web 2>/dev/null
    sudo rm -rf /var/www/simple_app
    sudo userdel -r webservice 2>/dev/null
    sudo rm -f /etc/systemd/system/ctf-web.service
    sudo systemctl daemon-reload 2>/dev/null
"

echo "Cleanup complete"