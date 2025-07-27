#!/bin/bash
# reset_ssh_brute_force.sh

echo "[+] Resetting SSH Brute Force to basic state..."

# Run cleanup first
./cleanup.sh

# Wait a moment for services to settle
sleep 3

# Run setup again
./setup.sh

echo "[+] SSH Brute Force scenario reset complete!"