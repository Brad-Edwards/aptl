#!/bin/bash
# reset_ftp_anonymous_access.sh

echo "[+] Resetting FTP Anonymous Access to basic state..."

# Run cleanup first
./cleanup.sh

# Wait for service to stop
sleep 2

# Run setup again
./setup.sh

echo "[+] FTP Anonymous Access scenario reset complete!"