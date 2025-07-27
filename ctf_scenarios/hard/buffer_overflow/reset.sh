#!/bin/bash
# reset_buffer_overflow.sh

echo "[+] Resetting Buffer Overflow to basic state..."

# Run cleanup first
./cleanup.sh

# Wait for services to stop
sleep 5

# Run setup again
./setup.sh

echo "[+] Buffer Overflow scenario reset complete!"