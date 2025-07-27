#!/bin/bash
# cleanup_buffer_overflow.sh

echo "[+] Cleaning up Buffer Overflow scenario..."

# Stop and disable network service
sudo systemctl stop vuln-network.service
sudo systemctl disable vuln-network.service
sudo rm -f /etc/systemd/system/vuln-network.service
sudo systemctl daemon-reload

# Remove binaries
sudo rm -f /usr/local/bin/vuln_service
sudo rm -f /usr/local/bin/network_vuln

# Remove flag
sudo rm -f /root/flag.txt

# Remove exploit development directory
rm -rf /home/$(whoami)/exploit_dev

# Clear core dumps
sudo rm -f /var/crash/*
sudo rm -f core.*

echo "[+] Buffer Overflow scenario cleaned up!"