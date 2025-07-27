#!/bin/bash
# reset_web_flag_hunt.sh

echo "[+] Resetting Web Flag Hunt to basic state..."

# Run cleanup first
./cleanup.sh

# Wait a moment
sleep 2

# Run setup again
./setup.sh

echo "[+] Web Flag Hunt scenario reset complete!"