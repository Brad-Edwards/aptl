#!/bin/sh
# Fail if the finalized immutable base contains state owned by an overlay.
set -eu

test ! -s /etc/machine-id
if find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -print |
    grep -q .
then
    exit 1
fi

for runtime_path in \
    /var/lib/docker \
    /var/lib/aptl \
    /opt/aptl/project/.aptl
do
    if test -d "$runtime_path" &&
        find "$runtime_path" -mindepth 1 -print -quit | grep -q .
    then
        exit 1
    fi
done

test ! -e /opt/aptl/project/.env
test -r /opt/aptl/offline/oci-images.tar
test -r /opt/aptl/project/participant-profiles/guided-purple-v1/profile.json
