#!/bin/bash
set -e

echo "=== Purple Team Lab Workstation Container Starting ==="

# Source shared entrypoint functions
source /opt/purple-team/scripts/entrypoint-base.sh

# Run common initialization (SSH, rsyslog, wazuh env)
run_common_entrypoint

# Generate CTF flags
generate_flags "workstation" "/home/dev-user/user.txt" "dev-user:dev-user"

echo "=== Workstation container initialization complete ==="

# Execute the main command (typically systemd)
exec "$@"
