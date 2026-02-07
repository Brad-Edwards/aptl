#!/bin/bash
set -e

echo "=== Purple Team Lab Reverse Engineering Container Starting ==="

# Source shared entrypoint functions
source /opt/purple-team/scripts/entrypoint-base.sh

# Run common initialization (SSH, rsyslog, wazuh env)
run_common_entrypoint

echo "=== Reverse engineering container initialization complete ==="

# Execute the main command (typically systemd)
exec "$@"
