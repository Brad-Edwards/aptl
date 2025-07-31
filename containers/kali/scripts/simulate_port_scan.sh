#!/bin/bash
source /home/kali/redteam_logging.sh

echo "=== Port Scan Simulation ==="
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>"
    echo "Example: $0 ${victim_private_ip}"
    exit 1
fi

TARGET="$1"
echo "Simulating port scan against $TARGET..."

# Log the reconnaissance activity
log_redteam_network "nmap_port_scan" "$TARGET" "1-1000" "initiated"
log_redteam_command "nmap -sS -p 1-1000 $TARGET" "$TARGET" "scan_started"

# Simulate scan results
echo "Scanning ports 1-1000..."
sleep 2

# Log discovered services
log_redteam_network "open_ports_discovered" "$TARGET" "22,80,443" "ssh,http,https_detected"
log_redteam_command "nmap -sV -p 22,80,443 $TARGET" "$TARGET" "version_scan_completed"

echo "✅ Port scan simulation complete!"
echo "📊 Check ${siem_type} for RedTeamActivity=network events"