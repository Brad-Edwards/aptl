#!/bin/sh
# Install the boot-time host-identity unit and prove the image ships no host
# private key (issue #1193). Run after the last step that installs packages.
set -eu
here=$(dirname "$0")
install -m 0755 "$here/aptl-host-identity" /usr/local/sbin/aptl-host-identity
install -m 0644 "$here/aptl-host-identity.service" \
    /etc/systemd/system/aptl-host-identity.service
systemctl enable aptl-host-identity.service
# A key deleted in a later layer still ships in the layer that created it, so
# each Dockerfile deletes keys in the same RUN that generates them. Fail the
# build if any earlier step left one behind.
for key in /etc/ssh/ssh_host_*_key /etc/ssl/private/ssl-cert-snakeoil.key; do
    if [ -e "$key" ]; then
        echo "private key baked into the image: $key" >&2
        exit 1
    fi
done
