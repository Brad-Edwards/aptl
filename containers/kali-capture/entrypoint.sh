#!/bin/sh
set -eu

install -d -m 0700 \
    /run/aptl-capture \
    /run/aptl-capture/sessions \
    /run/aptl-inner \
    /var/log/aptl/captures
# Debian's OpenSSH privilege-separation directory lives on the read-only
# container's ephemeral /run tmpfs, so recreate it on every start.
install -d -m 0755 /run/sshd
chown kali:kali \
    /run/aptl-capture \
    /run/aptl-capture/sessions \
    /run/aptl-inner \
    /var/log/aptl/captures
install -m 0600 /dev/null /run/aptl-capture/admission.lock
chown kali:kali /run/aptl-capture/admission.lock
install -d -m 0700 /run/aptl-sshd

install -m 0400 /run/aptl-source/inner_key /run/aptl-inner/id_ed25519
chown kali:kali /run/aptl-inner/id_ed25519
install -m 0444 -o root -g root \
    /run/aptl-source/outer_authorized_keys \
    /run/aptl-inner/authorized_keys
ssh-keygen -q -t ed25519 -N '' -f /run/aptl-sshd/ssh_host_ed25519_key

# The broker exposes no participant ingress until the host has bound this
# exact sidecar to the admitted plan and run.
while [ ! -f /run/aptl-capture/authority.json ]; do
    sleep 0.1
done
chmod 0600 /run/aptl-capture/authority.json
chown kali:kali /run/aptl-capture/authority.json

# Pin the already-relocated Kali sshd before accepting an outer session.
attempt=0
while ! ssh-keyscan -T 2 -p 2222 127.0.0.1 > /run/aptl-inner/known_hosts.tmp 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
        echo "kali capture broker: inner SSH endpoint unavailable" >&2
        exit 1
    fi
    sleep 0.5
done
mv /run/aptl-inner/known_hosts.tmp /run/aptl-inner/known_hosts
chmod 0444 /run/aptl-inner/known_hosts
chown kali:kali /run/aptl-inner/known_hosts

set +e
/usr/sbin/sshd -D -e -f /etc/aptl/sshd_config
status=$?
set -e
if [ -f /run/aptl-capture/quiesce ]; then
    exec sleep infinity
fi
exit "$status"
