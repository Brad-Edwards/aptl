#!/bin/sh
# Run only in a disposable CI overlay, after Docker starts.
set -u
exec >/var/log/aptl-seat-qualification.log 2>&1

echo 'seat-qualification: booted'
docker info --format 'docker-server={{.ServerVersion}}'
docker_status=$?
docker compose version
compose_status=$?
if test "$docker_status" -eq 0 && test "$compose_status" -eq 0; then
    docker load --input /opt/aptl/offline/oci-images.tar
    load_status=$?
else
    load_status=1
fi
if test "$load_status" -eq 0; then
    docker run --rm --network none debian:13-slim /bin/true
    run_status=$?
else
    run_status=1
fi
echo "seat-qualification: docker=$docker_status compose=$compose_status load=$load_status run=$run_status"

if test "$run_status" -eq 0; then
    timeout 1800 /usr/local/bin/aptl lab start \
        --project-dir /opt/aptl/project --offline-staged
    lab_status=$?
else
    lab_status=1
fi
echo "seat-qualification: lab=$lab_status"

if test "$lab_status" -eq 0; then
    PYTHONPATH=/opt/aptl/app:/opt/aptl/python /usr/bin/python3 - <<'PYTHON'
from pathlib import Path
import json
import socket
from aptl.appliance.access_service import _run_qualification_attempt
from aptl.validation import participant_mcp_smoke

original_call = participant_mcp_smoke.call_mcp_tool
def traced_call(*args, **kwargs):
    result = original_call(*args, **kwargs)
    if args[1] == 'kali_run_command':
        for block in result.get('content', []):
            if block.get('type') != 'text':
                continue
            try:
                payload = json.loads(block.get('text', '{}'))
            except (TypeError, ValueError):
                continue
            if not isinstance(payload, dict) or payload.get('success') is not False:
                continue
            error = str(payload.get('error', '')).lower()
            categories = (
                'enoent', 'econnrefused', 'etimedout', 'ehostunreach',
                'enetunreach', 'econnreset', 'authentication', 'permission',
                'connection', 'handshake', 'timeout', 'closed', 'key',
                'refused', 'denied', 'activation', 'unauthorized',
            )
            print('seat-qualification: red-error-categories=' + ','.join(
                name for name in categories if name in error
            ))
    return result
participant_mcp_smoke.call_mcp_tool = traced_call

print('seat-qualification: red-key-present=' + str(
    (Path.home() / '.ssh' / 'aptl_lab_key').is_file()
))
try:
    with socket.create_connection(('172.20.1.30', 22), timeout=3):
        print('seat-qualification: red-port=open')
except OSError as exc:
    print('seat-qualification: red-port=' + type(exc).__name__)

checks = _run_qualification_attempt(Path('/opt/aptl/project'))
print('seat-qualification: mcp-checks=' + str(len(checks)))
print('seat-qualification: mcp-statuses=' + ','.join(check.status for check in checks))
if not checks or any(check.status != 'passed' for check in checks):
    raise SystemExit(1)
PYTHON
    mcp_status=$?
else
    mcp_status=1
fi
echo "seat-qualification: mcp=$mcp_status"
printf 'docker=%s compose=%s load=%s run=%s\nlab=%s\nmcp=%s\n' \
    "$docker_status" "$compose_status" "$load_status" "$run_status" \
    "$lab_status" "$mcp_status" \
    >/var/log/aptl-seat-qualification.result
sync
systemctl poweroff --force
exit 0
