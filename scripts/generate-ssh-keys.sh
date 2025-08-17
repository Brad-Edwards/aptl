#!/bin/bash
set -e

# APTL Local SSH Key Generation Script
# Generates SSH key pairs for lab access

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$(dirname "$SCRIPT_DIR")/keys"
HOST_SSH_DIR="$HOME/.ssh"

echo "=== APTL Local SSH Key Generation ==="
echo "Keys directory: $KEYS_DIR"
echo "Host SSH directory: $HOST_SSH_DIR"

# Create directories
mkdir -p "$KEYS_DIR"
mkdir -p "$HOST_SSH_DIR"

# Generate lab SSH key pair if it doesn't exist
if [ ! -f "$HOST_SSH_DIR/aptl_lab_key" ]; then
    echo "Generating lab SSH key pair..."
    ssh-keygen -t rsa -b 2048 -f "$HOST_SSH_DIR/aptl_lab_key" -N "" -C "aptl-local-lab"
    echo "✅ Generated SSH key pair: $HOST_SSH_DIR/aptl_lab_key"
else
    echo "✅ Lab SSH key already exists: $HOST_SSH_DIR/aptl_lab_key"
fi

# Copy public key to keys directory for container mounting
cp "$HOST_SSH_DIR/aptl_lab_key.pub" "$KEYS_DIR/aptl_lab_key.pub"
cp "$HOST_SSH_DIR/aptl_lab_key.pub" "$KEYS_DIR/authorized_keys"
echo "✅ Copied public key to: $KEYS_DIR/aptl_lab_key.pub"
echo "✅ Copied authorized_keys to: $KEYS_DIR/authorized_keys"

# Set correct permissions
chmod 600 "$HOST_SSH_DIR/aptl_lab_key"
chmod 644 "$HOST_SSH_DIR/aptl_lab_key.pub"
chmod 644 "$KEYS_DIR/aptl_lab_key.pub"
chmod 644 "$KEYS_DIR/authorized_keys"

echo ""
echo "=== SSH Key Setup Complete ==="
echo "Private key: $HOST_SSH_DIR/aptl_lab_key"
echo "Public key:  $HOST_SSH_DIR/aptl_lab_key.pub"
echo ""
echo "To connect to containers:"
echo "  victim:      ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022"
echo "  juice-shop:  ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2024"
echo "  kali:        ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023"
echo ""
echo "For MCP server, the key path is: ~/.ssh/aptl_lab_key"