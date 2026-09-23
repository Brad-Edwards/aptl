#!/bin/sh
# Install everything a seat needs, so the guest boots ready to run the lab.
#
# This runs once, during the bake, inside the image being built. When it
# finishes the guest holds Docker, the APTL runtime, and every container image
# TechVault starts, already in the local daemon. First boot resolves nothing,
# pulls nothing and builds nothing.
set -eu
umask 022

stage=/opt/aptl-stage
test "$(id -u)" -eq 0
test -d "$stage"

# --- Docker ------------------------------------------------------------
# The base image ships Docker; this only guarantees the daemon is enabled for
# the guest's own use and refuses to continue if it is absent, rather than
# reaching out to a package repository during an offline bake.
command -v dockerd >/dev/null || {
    echo 'seat image base must provide Docker' >&2
    exit 1
}
systemctl enable docker.service

# --- APTL runtime ------------------------------------------------------
python3 -m venv /opt/aptl/venv
# --no-index keeps the bake offline: everything resolves from the staged
# wheelhouse, which was built from the hash-locked runtime closure.
/opt/aptl/venv/bin/pip install --no-index --find-links "$stage/wheelhouse" \
    "$stage"/wheelhouse/aptl_labs-*.whl
ln -sf /opt/aptl/venv/bin/aptl /usr/local/bin/aptl
/opt/aptl/venv/bin/aptl --version >/dev/null

# --- container images --------------------------------------------------
# Load every image into the guest daemon now. This is the whole point of the
# bake: a participant's first boot must not pull thirty images over whatever
# network the venue has.
dockerd --data-root /var/lib/docker >/tmp/dockerd-bake.log 2>&1 &
daemon=$!
attempts=0
until docker info >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    # A daemon that will not come up inside the bake is a build failure, not
    # something to wait on indefinitely.
    if test "$attempts" -gt 120; then
        echo 'Docker daemon did not start during the seat image bake' >&2
        cat /tmp/dockerd-bake.log >&2
        exit 1
    fi
    sleep 1
done

docker load --input "$stage/images.tar"
loaded=$(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -cv '^<none>')
test "$loaded" -ge 25 || {
    echo "seat image loaded only $loaded container images" >&2
    exit 1
}

docker image ls --format '{{.Repository}}:{{.Tag}}\t{{.ID}}' \
    | sort >/opt/aptl/preloaded-images.txt

kill "$daemon"
wait "$daemon" 2>/dev/null || true
rm -f /tmp/dockerd-bake.log

# --- first boot --------------------------------------------------------
install -m 0755 "$stage/aptl-appliance-first-boot" /usr/local/sbin/
install -m 0644 "$stage/aptl-appliance-first-boot.service" \
    /etc/systemd/system/
install -m 0644 "$stage/aptl-launch.mount" /etc/systemd/system/
systemctl enable aptl-launch.mount
systemctl enable aptl-appliance-first-boot.service

# The bake must leave no staged payload behind; the overlay a participant runs
# is created from this disk and should carry nothing but the installed system.
rm -rf "$stage"
