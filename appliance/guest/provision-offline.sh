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
test -f "$payload_dir/claude-runtime.tar"
for filename in desktop-compose.yml desktop-nginx.conf seat-desktop.py seat-privileges.py desktop-handoff.py desktop-mcp-smoke.py desktop-session.sh guac-schema.sql; do
    test -f "$payload_dir/$filename"
done

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
install -d -m 0755 /opt/aptl/claude
tar --extract --file "$payload_dir/claude-runtime.tar" \
    --directory /opt/aptl/claude --no-same-owner
ln -s /opt/aptl/claude/node_modules/.bin/claude /usr/local/bin/claude
systemctl disable avahi-daemon.service avahi-daemon.socket 2>/dev/null || true
systemctl mask avahi-daemon.service avahi-daemon.socket 2>/dev/null || true

# The account is locked in the immutable disk. The disposable overlay creates
# its xrdp password on first boot; Guacamole supplies it automatically.
if ! getent passwd aptl >/dev/null; then
    useradd --create-home --home-dir /home/aptl --shell /bin/bash aptl
fi
# The signed disk never grants the participant root-equivalent access. A
# selected administrative overlay applies its sudo rule before desktop login.
gpasswd --delete aptl docker 2>/dev/null || true
gpasswd --delete aptl sudo 2>/dev/null || true
rm -f /etc/sudoers.d/90-aptl-desktop
printf 'xfce4-session\n' >/home/aptl/.xsession
install -d -m 0755 /home/aptl/.config/autostart \
    /home/aptl/.config/xfce4/xfconf/xfce-perchannel-xml
cat >/home/aptl/.config/autostart/aptl-desktop.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=APTL Desktop
Exec=/usr/local/bin/aptl-desktop-session
X-GNOME-Autostart-enabled=true
EOF
cat >/home/aptl/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfwm4" version="1.0">
  <property name="general" type="empty">
    <property name="use_compositing" type="bool" value="false"/>
  </property>
</channel>
EOF
python3 - <<'PYTHON'
import json
from pathlib import Path

root = Path('/home/aptl')
servers = {
    'red': ('mcp-red',),
    'blue': ('mcp-wazuh', 'mcp-indexer', 'mcp-network',
             'mcp-threatintel', 'mcp-casemgmt', 'mcp-soar'),
}
for role, names in servers.items():
    config = {'mcpServers': {
        f'aptl-{name.removeprefix("mcp-")}': {
            'command': 'node',
            'args': [f'/opt/aptl/project/mcp/{name}/build/index.js'],
        }
        for name in names
    }}
    (root / f'{role}.mcp.json').write_text(
        json.dumps(config, separators=(',', ':')), encoding='utf-8'
    )
PYTHON
cat >/etc/xrdp/startwm.sh <<'EOF'
#!/bin/sh
if [ -r /etc/profile ]; then . /etc/profile; fi
if [ -r "$HOME/.profile" ]; then . "$HOME/.profile"; fi
exec /usr/bin/startxfce4
EOF
chmod 0755 /etc/xrdp/startwm.sh
sed -i 's/^max_bpp=.*/max_bpp=16/' /etc/xrdp/xrdp.ini
if ! grep -q '^tcp_send_buffer_bytes=' /etc/xrdp/xrdp.ini; then
    sed -i '/^tcp_nodelay=true/a tcp_send_buffer_bytes=4194304\ntcp_recv_buffer_bytes=4194304' /etc/xrdp/xrdp.ini
fi
usermod --append --groups ssl-cert xrdp
chown -R aptl:aptl /home/aptl

install -d -m 0755 /opt/aptl/desktop
for filename in desktop-compose.yml desktop-nginx.conf seat-desktop.py seat-privileges.py desktop-handoff.py desktop-mcp-smoke.py guac-schema.sql; do
    install -m 0444 "$payload_dir/$filename" "/opt/aptl/desktop/$filename"
done
install -m 0755 "$payload_dir/desktop-session.sh" \
    /usr/local/bin/aptl-desktop-session
cat >/usr/local/bin/start-seat-desktop <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/aptl/desktop/seat-desktop.py
EOF
chmod 0755 /usr/local/bin/start-seat-desktop
systemctl disable xrdp.service

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
systemctl enable run-aptl\\x2dlaunch.mount
systemctl enable aptl-appliance-first-boot.service

# The release contains installed inputs only. Per-overlay identity, .env,
# service credentials, Docker writable state, and run evidence are created
# after the launcher has attached a disposable overlay.
rm -rf "$stage"
