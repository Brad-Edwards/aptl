#!/bin/bash
# reset_multi_stage_attack.sh

echo "[+] Resetting Multi-Stage Attack to basic state..."

# Run cleanup first
./cleanup.sh

# Wait for services to stop
sleep 10

# Run setup again
./setup.sh

echo "[+] Multi-Stage Attack scenario reset complete!"