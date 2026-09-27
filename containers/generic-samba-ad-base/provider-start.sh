#!/bin/sh
set -eu

ready=/run/aptl-samba-provider.ready
while [ ! -f "$ready" ]; do
    sleep 0.1
done

exec /usr/sbin/samba -F --no-process-group
