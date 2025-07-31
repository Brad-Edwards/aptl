#!/bin/bash
set -e

echo "=== Quick Container Test ==="

# Cleanup any existing test container
docker rm -f kali-test 2>/dev/null || true

# Start container
echo "Starting container..."
docker run -d --name kali-test -p 2222:22 aptl/kali-red-team:latest

# Wait a moment for startup
sleep 5

# Test SSH is running
if docker exec kali-test pgrep sshd > /dev/null; then
    echo "✅ SSH service running"
else
    echo "❌ SSH service failed"
    exit 1
fi

echo ""
echo "Container ready!"
echo "SSH: ssh -p 2222 kali@localhost"
echo "Password: kali"
echo ""
echo "Cleanup: docker rm -f kali-test"