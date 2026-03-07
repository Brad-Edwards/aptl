#!/bin/bash
set -e

echo "=== Purple Team Lab Victim Container Starting ==="

# Source shared entrypoint functions
source /opt/purple-team/scripts/entrypoint-base.sh

# Run common initialization (SSH, rsyslog, wazuh env)
run_common_entrypoint

# Generate CTF flags
generate_flags "victim" "/home/labadmin/user.txt" "labadmin:labadmin"

echo "=== Victim container initialization complete ==="

# Execute the main command (typically systemd)
exec "$@"
