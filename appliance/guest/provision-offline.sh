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
test -f "$payload_dir/aptl-wheel-requirements.txt"
test -f "$payload_dir/project.tar"
test -f "$payload_dir/oci-images.tar"
test -f "$payload_dir/appliance-release.env"
test -f "$payload_dir/aptl-appliance-first-boot"
test -f "$payload_dir/aptl-appliance-first-boot.service"
test -f "$payload_dir/aptl-launch.mount"
test -d "$payload_dir/system-packages"
test -f "$payload_dir/system-packages.sha256"

set -- "$payload_dir"/wheelhouse/pip-*.whl
test "$#" -eq 1
test -f "$1"
pip_wheel=$1
install -d -m 0755 /opt/aptl /opt/aptl/python /usr/local/bin
PYTHONPATH="$1" python3 -m pip install --no-index --only-binary=:all: \
    --target /opt/aptl/python \
    --ignore-installed \
    --require-hashes \
    --find-links "$payload_dir/wheelhouse" \
    -r "$payload_dir/requirements.txt"

# Keep the application wheel separate from the dependency closure. pip's
# --target install does not merge an existing bin directory, so installing the
# wheel into the dependency target would silently omit its aptl entrypoint.
set -- "$payload_dir"/wheelhouse/aptl_labs-*.whl
test "$#" -eq 1
test -f "$1"
PYTHONPATH="$pip_wheel" python3 -m pip install \
    --no-index --no-deps --ignore-installed --target /opt/aptl/app \
    --require-hashes --find-links "$payload_dir/wheelhouse" \
    -r "$payload_dir/aptl-wheel-requirements.txt"

# The Ubuntu base marks its system Python as externally managed and does not
# ship ensurepip. Keep the authenticated application closure isolated under
# /opt and expose only fixed launchers through the system PATH.
cat > /usr/local/bin/aptl <<'EOF'
#!/bin/sh
PYTHONPATH=/opt/aptl/app:/opt/aptl/python exec /usr/bin/python3 /opt/aptl/app/bin/aptl "$@"
EOF
cat > /usr/local/bin/raes <<'EOF'
#!/bin/sh
PYTHONPATH=/opt/aptl/app:/opt/aptl/python exec /usr/bin/python3 /opt/aptl/python/bin/raes "$@"
EOF
cat > /usr/local/bin/aptl-misp-suricata-sync <<'EOF'
#!/bin/sh
PYTHONPATH=/opt/aptl/app:/opt/aptl/python exec /usr/bin/python3 /opt/aptl/app/bin/aptl-misp-suricata-sync "$@"
EOF
chmod 0755 /usr/local/bin/aptl /usr/local/bin/raes \
    /usr/local/bin/aptl-misp-suricata-sync

# Install the content-locked guest runtime without granting the build guest
# network access. Suppress maintainer-script service starts until first boot.
(cd "$payload_dir/system-packages" && \
    sha256sum --check --strict ../system-packages.sha256)
test ! -e /usr/sbin/policy-rc.d
cat > /usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 0755 /usr/sbin/policy-rc.d
dpkg --unpack "$payload_dir"/system-packages/*.deb
dpkg --configure --pending
rm -f /usr/sbin/policy-rc.d
systemctl enable docker.service

install -d -m 0755 /opt/aptl/project
tar --extract --file "$payload_dir/project.tar" \
    --directory /opt/aptl/project --no-same-owner
# Only immutable, scanned release inputs exist here. Runtime credentials and
# evidence are created later under the first-boot service's private umask.
chmod -R a+rX /opt/aptl/app /opt/aptl/python /opt/aptl/project
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
install -m 0644 "$payload_dir/aptl-launch.mount" \
    /etc/systemd/system/run-aptl\\x2dlaunch.mount
install -d -m 0711 /var/lib/aptl
if ! getent passwd aptl-mcp >/dev/null; then
    useradd --system --no-create-home --home-dir /var/lib/aptl/mcp \
        --shell /bin/sh aptl-mcp
fi
# sshd disables every password method. An empty password field keeps the
# account eligible for public-key forced commands on builds that reject locked
# accounts before consulting AuthorizedKeysFile.
passwd --delete aptl-mcp >/dev/null
if getent group docker >/dev/null; then
    usermod --append --groups docker aptl-mcp
fi
install -d -m 0700 -o aptl-mcp -g aptl-mcp /var/lib/aptl/mcp
systemctl enable run-aptl\\x2dlaunch.mount
systemctl enable aptl-appliance-first-boot.service

# The release contains installed inputs only. Per-overlay identity, .env,
# service credentials, Docker writable state, and run evidence are created
# after the launcher has attached a disposable overlay.
rm -rf "$stage"
