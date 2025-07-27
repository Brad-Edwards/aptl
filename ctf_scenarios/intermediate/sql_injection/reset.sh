#!/bin/bash
# reset_sql_injection.sh

echo "[+] Resetting SQL Injection to basic state..."

# Run cleanup first
./cleanup.sh

# Wait for services to stop
sleep 5

# Run setup again
./setup.sh

echo "[+] SQL Injection scenario reset complete!"