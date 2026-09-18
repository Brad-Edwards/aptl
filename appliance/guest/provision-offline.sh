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
# Bootstrap cannot import APTL yet. Admit a regular-file-only archive namespace
# before installing anything; the signed release verifier authenticates bytes.
python3 - "$payload_archive" "$payload_dir" <<'PYTHON'
import pathlib
import shutil
import sys
import tarfile

root = pathlib.Path(sys.argv[2])
with tarfile.open(sys.argv[1], 'r:') as archive:
    members = archive.getmembers()
    seen, files = set(), set()
    if len(members) > 500000 or sum(item.size for item in members) > 500 * 1024**3:
        raise SystemExit('payload limits exceeded')
    for item in members:
        name = item.name.rstrip('/')
        path = pathlib.PurePosixPath(name)
        if (not name or path.is_absolute() or '\\' in name or '\0' in name
                or any(part in {'', '.', '..'} for part in name.split('/'))
                or name in seen or not (item.isfile() or item.isdir())):
            raise SystemExit('unsafe payload member')
        seen.add(name)
        if item.isfile():
            files.add(name)
    if any(parent.as_posix() in files for name in seen for parent in pathlib.PurePosixPath(name).parents):
        raise SystemExit('payload file used as a directory')
    for item in members:
        target = root / item.name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if item.isdir():
            target.mkdir(exist_ok=True, mode=0o700)
        else:
            with target.open('xb') as output, archive.extractfile(item) as source:
                shutil.copyfileobj(source, output, 1024 * 1024)
PYTHON

test -d "$payload_dir/wheelhouse"
test -f "$payload_dir/project.tar"
test -f "$payload_dir/oci-images.tar"
test -f "$payload_dir/appliance-release.env"
test -f "$payload_dir/aptl-appliance-first-boot"
test -f "$payload_dir/aptl-appliance-first-boot.service"
test -f "$payload_dir/aptl-launch.mount"

python3 -m pip install --no-index --only-binary=:all: --require-hashes \
    --find-links "$payload_dir/wheelhouse" \
    -r "$payload_dir/requirements.txt"
aptl appliance validate-inputs --staging-dir "$payload_dir"

install -d -m 0755 /opt/aptl/project
tar --extract --file "$payload_dir/project.tar" \
    --directory /opt/aptl/project --no-same-owner
install -d -m 0755 /opt/aptl/offline
install -m 0444 "$payload_dir/inputs.json" /opt/aptl/offline/inputs.json
install -m 0444 "$payload_dir/oci-images.tar" \
    /opt/aptl/offline/oci-images.tar

install -d -m 0755 /etc/aptl /usr/local/libexec
install -m 0644 "$payload_dir/appliance-release.env" \
    /etc/aptl/appliance-release.env
install -m 0755 "$payload_dir/aptl-appliance-first-boot" \
    /usr/local/libexec/aptl-appliance-first-boot
install -m 0644 "$payload_dir/aptl-appliance-first-boot.service" \
    /etc/systemd/system/aptl-appliance-first-boot.service
install -m 0644 "$payload_dir/aptl-launch.mount" \
    /etc/systemd/system/run-aptl\\x2dlaunch.mount
install -d -m 0700 /var/lib/aptl
if ! getent passwd aptl-mcp >/dev/null; then
    useradd --system --create-home --home-dir /var/lib/aptl/mcp \
        --shell /bin/sh aptl-mcp
fi
# sshd disables every password method. An empty password field keeps the
# account eligible for public-key forced commands on builds that reject locked
# accounts before consulting AuthorizedKeysFile.
passwd --delete aptl-mcp >/dev/null
if getent group docker >/dev/null; then
    usermod --append --groups docker aptl-mcp
fi
chown aptl-mcp:aptl-mcp /var/lib/aptl/mcp
chmod 0700 /var/lib/aptl/mcp
systemctl enable run-aptl\\x2dlaunch.mount
systemctl enable aptl-appliance-first-boot.service

# The release contains installed inputs only. Per-overlay identity, .env,
# service credentials, Docker writable state, and run evidence are created
# after the launcher has attached a disposable overlay.
rm -rf "$stage"
