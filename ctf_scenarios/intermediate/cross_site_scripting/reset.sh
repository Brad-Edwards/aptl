#!/bin/bash
# reset_cross_site_scripting.sh

echo "[+] Resetting Cross-Site Scripting to basic state..."

./cleanup.sh
sleep 2
./setup.sh

echo "[+] Cross-Site Scripting scenario reset complete!"
