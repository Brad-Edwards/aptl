#!/bin/bash
# reset_telnet_weak_auth.sh

echo "[+] Resetting Telnet Weak Authentication to basic state..."

# Run cleanup first
./cleanup.sh

# Wait for services to stop
sleep 3

# Run setup again
./setup.sh

echo "[+] Telnet Weak Authentication scenario reset complete!"