#!/bin/sh
# Install everything a seat needs, so the guest boots ready to run the lab.
#
# This runs once, during the bake, inside the image being built. When it
# finishes the guest holds Docker, the APTL runtime, and every container image
# TechVault starts, already in the local daemon. First boot resolves nothing,
# pulls nothing and builds nothing.
set -eu
umask 022

# virt-customize runs with a minimal PATH that need not include
# /usr/local/bin, which is where the staged Docker lands.
PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

stage=/opt/aptl-stage
test "$(id -u)" -eq 0
test -d "$stage"

# --- Docker ------------------------------------------------------------
# The cloud base ships no Docker and the guest reaches no package repository
# during the bake, so the engine arrives as Docker's own static build, staged
# and digest-verified on the host. It carries dockerd, containerd, runc and
# the shim, so nothing is resolved here. Extracting straight into place keeps
# the payload from leaving a copy behind in the image.
tar --extract --file "$stage/docker-static.tgz" --directory /usr/local/bin \
    --strip-components=1 --no-same-owner
chmod 0755 /usr/local/bin/dockerd /usr/local/bin/docker /usr/local/bin/containerd \
    /usr/local/bin/runc /usr/local/bin/containerd-shim-runc-v2 \
    /usr/local/bin/docker-proxy /usr/local/bin/docker-init /usr/local/bin/ctr
install -m 0644 "$stage/docker.service" /etc/systemd/system/docker.service
getent group docker >/dev/null || groupadd --system docker
test -x /usr/local/bin/dockerd || {
    echo 'seat image bake could not install Docker' >&2
    exit 1
}
systemctl enable docker.service

# --- APTL runtime ------------------------------------------------------
# The cloud base ships no ensurepip, and the guest has no network, so the
# environment is created without pip and pip is bootstrapped from its own
# staged wheel -- a wheel is a zip, and pip inside one is importable.
python3 -m venv --without-pip /opt/aptl/venv
pip_wheel=$(ls "$stage"/wheelhouse/pip-*.whl)
# --no-index keeps this offline: everything resolves from the staged
# wheelhouse, which was built from the hash-locked runtime closure.
/opt/aptl/venv/bin/python "$pip_wheel/pip" install --no-index \
    --find-links "$stage/wheelhouse" "$pip_wheel"
/opt/aptl/venv/bin/python -m pip install --no-index \
    --find-links "$stage/wheelhouse" "$stage"/wheelhouse/aptl_labs-*.whl
ln -sf /opt/aptl/venv/bin/aptl /usr/local/bin/aptl
/opt/aptl/venv/bin/aptl --version >/dev/null

# --- container images --------------------------------------------------
# The store was built on the host by this same Docker version, because the
# build appliance cannot run a daemon. Restoring it whole is what makes first
# boot pull-free: every image is already in the local store.
install -d -m 0711 /var/lib/docker
tar --extract --file "$stage/guest-docker.tar" --directory /var/lib/docker \
    --no-same-owner --same-permissions
test -d /var/lib/docker/image || {
    echo 'seat image has no restored Docker image store' >&2
    exit 1
}

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
