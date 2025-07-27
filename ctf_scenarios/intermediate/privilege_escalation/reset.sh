#!/bin/bash
# reset_privilege_escalation.sh

echo "[+] Resetting Privilege Escalation to basic state..."

# Run cleanup first
./cleanup.sh

# Wait a moment
sleep 3

# Run setup again
./setup.sh

echo "[+] Privilege Escalation scenario reset complete!"