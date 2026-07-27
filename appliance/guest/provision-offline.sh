#!/bin/sh
# Install an already-staged APTL release into an offline supported guest base.
set -eu
umask 077

stage=/opt/aptl-stage
payload_archive="$stage/offline-payload.tar"
payload_dir="$stage/payload"

test "$(id -u)" -eq 0
test -f "$payload_archive"
test ! -e "$payload_dir"
install -d -m 0700 "$payload_dir"
tar --extract --file "$payload_archive" --directory "$payload_dir" --no-same-owner

test -d "$payload_dir/wheelhouse"
test -f "$payload_dir/project.tar"
test -f "$payload_dir/oci-images.tar"
test -f "$payload_dir/appliance-release.env"
test -f "$payload_dir/aptl-appliance-first-boot"
test -f "$payload_dir/aptl-appliance-first-boot.service"

. "$payload_dir/appliance-release.env"
: "${APTL_APPLIANCE_VERSION:?missing staged APTL version}"
python3 -m pip install --no-index \
    --find-links "$payload_dir/wheelhouse" \
    "aptl-labs==$APTL_APPLIANCE_VERSION"

install -d -m 0755 /opt/aptl/project
tar --extract --file "$payload_dir/project.tar" \
    --directory /opt/aptl/project --no-same-owner
install -d -m 0755 /opt/aptl/offline
install -m 0444 "$payload_dir/oci-images.tar" \
    /opt/aptl/offline/oci-images.tar

install -d -m 0755 /etc/aptl /usr/local/libexec
install -m 0644 "$payload_dir/appliance-release.env" \
    /etc/aptl/appliance-release.env
install -m 0755 "$payload_dir/aptl-appliance-first-boot" \
    /usr/local/libexec/aptl-appliance-first-boot
install -m 0644 "$payload_dir/aptl-appliance-first-boot.service" \
    /etc/systemd/system/aptl-appliance-first-boot.service
install -d -m 0700 /var/lib/aptl
systemctl enable aptl-appliance-first-boot.service

# The release contains installed inputs only. Per-overlay identity, .env,
# service credentials, Docker writable state, and run evidence are created
# after the launcher has attached a disposable overlay.
rm -rf "$payload_dir"
