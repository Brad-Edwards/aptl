#!/bin/bash
# =============================================================================
# setup-rdp.sh -- add RDP access + a light desktop to an APTL Arsenal range.
# =============================================================================
# Participants RDP into the range host and drive the demo from there: a terminal
# for Claude Code (the MCP agent) and Firefox for the Wazuh / SOC web UIs. Run
# once on the box before baking the AMI so every clone has RDP on :3389.
#
# The RDP password for the `ubuntu` user is set here; override with APTL_RDP_PASS.
# Distribute it alongside the per-range .rdp files.
# =============================================================================
set -uo pipefail

RDP_USER="${APTL_RDP_USER:-ubuntu}"
RDP_PASS="${APTL_RDP_PASS:-AptlArsenal!2026}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PARTICIPANT_HOME="$(getent passwd "$RDP_USER" | cut -d: -f6)"

echo "=== setup-rdp starting $(date -u) ==="
export DEBIAN_FRONTEND=noninteractive
# Wait up to 10 min for the dpkg lock (Ubuntu's unattended-upgrades holds it on a
# fresh boot) instead of failing immediately.
APT=(sudo -E apt-get -o DPkg::Lock::Timeout=600 -y)
"${APT[@]}" update >/tmp/rdp-apt.log 2>&1
# xfce4 (light desktop) + xfce4-terminal + xrdp + dbus-x11 for the session.
"${APT[@]}" install xrdp xorgxrdp xfce4 xfce4-terminal dbus-x11 >>/tmp/rdp-apt.log 2>&1
# Browser for the SOC web UIs. Use the NATIVE epiphany-browser .deb, not the
# Firefox snap: snap apps take 30-60s+ to first-launch from squashfs in an xrdp
# session (reads as "the box is frozen"). Native = instant.
"${APT[@]}" install epiphany-browser >>/tmp/rdp-apt.log 2>&1 || true

# xfce pulls in avahi-daemon (mDNS on UDP :5353), which collides with the aptl
# `dns` node's port and breaks `aptl lab start` on a fresh boot. Not needed for
# the workshop -- mask it so it never grabs the port.
sudo systemctl disable --now avahi-daemon.service avahi-daemon.socket 2>/dev/null || true
sudo systemctl mask avahi-daemon.service avahi-daemon.socket 2>/dev/null || true

# Session: xfce for the RDP user.
echo "xfce4-session" | sudo tee "/home/$RDP_USER/.xsession" >/dev/null
sudo chown "$RDP_USER:$RDP_USER" "/home/$RDP_USER/.xsession"
# System-wide default so xrdp's Xorg session starts xfce even without ~/.xsession.
sudo tee /etc/xrdp/startwm.sh >/dev/null <<'WM'
#!/bin/sh
if [ -r /etc/profile ]; then . /etc/profile; fi
if [ -r "$HOME/.profile" ]; then . "$HOME/.profile"; fi
exec /usr/bin/startxfce4
WM
sudo chmod +x /etc/xrdp/startwm.sh

# xrdp user must read the TLS key it generates.
sudo adduser xrdp ssl-cert >/dev/null 2>&1 || true

# Set the RDP login password for the participant user.
echo "$RDP_USER:$RDP_PASS" | sudo chpasswd

# A desktop launcher so participants see how to start the agent immediately.
sudo -u "$RDP_USER" mkdir -p "/home/$RDP_USER/Desktop"
sudo -u "$RDP_USER" tee "/home/$RDP_USER/Desktop/Start-Claude-Agent.desktop" >/dev/null <<'DESK'
[Desktop Entry]
Version=1.0
Type=Application
Name=Start Claude Agent
Comment=Open a terminal in the aptl repo and launch Claude Code
Exec=xfce4-terminal --working-directory=/home/ubuntu/aptl3 -e "bash -lc 'echo Run: claude ; exec bash'"
Icon=utilities-terminal
Terminal=false
DESK
sudo chmod +x "/home/$RDP_USER/Desktop/Start-Claude-Agent.desktop" 2>/dev/null || true

# Put the participant guide and credentials in the browser at login. Epiphany
# accepts one URL per invocation; later invocations join the existing process as
# tabs. MISP redirects to its canonical hostname, so keep that host mapped to
# the live container address instead of leaving the browser on an unresolved
# redirect.
sudo cp "$REPO_ROOT/docs/workshop/arsenal-2026/handout.md" \
    "$PARTICIPANT_HOME/Desktop/APTL Participant Guide.md"
sudo python3 - "$PARTICIPANT_HOME/Desktop/APTL Participant Guide.md" \
    "$PARTICIPANT_HOME/Desktop/APTL Participant Guide.html" <<'PY'
from html import escape
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
body = escape(source)
Path(sys.argv[2]).write_text(
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    '<title>APTL Participant Guide</title><style>'
    'body{font-family:DejaVu Sans,Arial,sans-serif;margin:2rem;color:#172033}'
    'pre{white-space:pre-wrap;max-width:1000px;line-height:1.45;'
    'font:15px/1.45 DejaVu Sans,Arial,sans-serif}'
    '</style></head><body><pre>' + body + '</pre></body></html>\n'
)
PY
sudo tee "$PARTICIPANT_HOME/Desktop/TechVault-Access.html" >/dev/null <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>TechVault SOC access</title>
<style>
body{font-family:DejaVu Sans,Arial,sans-serif;margin:2rem;color:#172033}
table{border-collapse:collapse;width:100%;max-width:920px}
th,td{border:1px solid #c8ced8;padding:.6rem .8rem;text-align:left}
th,code{background:#eef1f6} code{padding:.1rem .3rem;border-radius:3px}
</style></head><body>
<h1>TechVault SOC service access</h1>
<p>Use these accounts in the console tabs.</p>
<table>
<tr><th>Service</th><th>URL</th><th>Username</th><th>Password</th></tr>
<tr><td>Wazuh Dashboard</td><td><a href="https://wazuh.dashboard/">https://wazuh.dashboard/</a></td><td><code>admin</code></td><td><code>SecretPassword</code></td></tr>
<tr><td>TheHive</td><td><a href="https://localhost:9000/">https://localhost:9000/</a></td><td><code>aptl-svc@thehive.local</code></td><td><code>AptlService2024!</code></td></tr>
<tr><td>Cortex</td><td><a href="http://localhost:9001/">http://localhost:9001/</a></td><td><code>aptl-svc@cortex.local</code></td><td><code>AptlCortexService2026!</code></td></tr>
<tr><td>Shuffle</td><td><a href="https://localhost:3443/">https://localhost:3443/</a></td><td><code>admin</code></td><td><code>ShuffleAdmin2024!</code></td></tr>
<tr><td>MISP</td><td><a href="https://misp.techvault.local/">https://misp.techvault.local/</a></td><td><code>admin@admin.test</code></td><td><code>admin</code></td></tr>
</table>
</body></html>
HTML

sudo tee /usr/local/sbin/aptl-refresh-misp-host.sh >/dev/null <<'HOSTS'
#!/usr/bin/env bash
set -euo pipefail
container="$(docker ps --format '{{.Names}}' | sed -n 's/-misp$//p' | head -1)-misp"
[ "$container" != '-misp' ]
ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$container" | awk '{print $1}')"
[ -n "$ip" ]
temporary="$(mktemp)"
awk '$2 != "misp.techvault.local" { print }' /etc/hosts >"$temporary"
printf '%s\t%s\n' "$ip" misp.techvault.local >>"$temporary"
cat "$temporary" >/etc/hosts
shred -u "$temporary"
HOSTS
sudo chmod 755 /usr/local/sbin/aptl-refresh-misp-host.sh
sudo tee /etc/systemd/system/aptl-misp-host.service >/dev/null <<'UNIT'
[Unit]
Description=Refresh the APTL MISP desktop hostname
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/aptl-refresh-misp-host.sh
UNIT
sudo tee /etc/systemd/system/aptl-misp-host.timer >/dev/null <<'UNIT'
[Unit]
Description=Keep the APTL MISP desktop hostname current

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=aptl-misp-host.service

[Install]
WantedBy=timers.target
UNIT

sudo tee /usr/local/bin/aptl-open-participant-browser.sh >/dev/null <<BROWSER
#!/usr/bin/env bash
set -u
urls=(
  'file://$PARTICIPANT_HOME/Desktop/TechVault-Access.html'
  'file://$PARTICIPANT_HOME/Desktop/APTL%20Participant%20Guide.html'
  'https://wazuh.dashboard/'
  'https://localhost:9000/'
  'http://localhost:9001/'
  'https://localhost:3443/'
  'https://misp.techvault.local/'
)
for url in "\${urls[@]}"; do
  epiphany-browser "\$url" >/tmp/aptl-participant-browser.log 2>&1 &
  sleep 1
done
BROWSER
sudo chmod 755 /usr/local/bin/aptl-open-participant-browser.sh
sudo -u "$RDP_USER" mkdir -p "$PARTICIPANT_HOME/.config/autostart"
sudo -u "$RDP_USER" tee "$PARTICIPANT_HOME/.config/autostart/20-aptl-browser.desktop" >/dev/null <<'DESK'
[Desktop Entry]
Type=Application
Name=APTL guide and SOC consoles
Comment=Open the credentials, participant guide, and SOC consoles
Exec=/usr/local/bin/aptl-open-participant-browser.sh
X-GNOME-Autostart-enabled=true
DESK
sudo systemctl daemon-reload
sudo systemctl enable aptl-misp-host.timer >/dev/null
sudo chown -R "$RDP_USER:$RDP_USER" "$PARTICIPANT_HOME/Desktop" "$PARTICIPANT_HOME/.config/autostart"

# Responsiveness over internet RDP: 32bpp at 1080p with the xfce compositor is
# heavy and reads as "the box is slow" even when it is idle. Cap to 16bpp and
# disable compositing -- the single biggest lag win.
sudo sed -i 's/^max_bpp=.*/max_bpp=16/' /etc/xrdp/xrdp.ini
# xrdp's default TCP send/recv buffers are 32KB, which starves throughput and is
# the top-reported cause of laggy window dragging over anything but a fast LAN
# (neutrinolabs/xrdp #1483/#2135/#2393). Bump to 4MB.
if ! grep -q '^tcp_send_buffer_bytes' /etc/xrdp/xrdp.ini; then
    sudo sed -i '/^tcp_nodelay=true/a tcp_send_buffer_bytes=4194304\ntcp_recv_buffer_bytes=4194304' /etc/xrdp/xrdp.ini
fi
sudo -u "$RDP_USER" mkdir -p "/home/$RDP_USER/.config/xfce4/xfconf/xfce-perchannel-xml"
sudo -u "$RDP_USER" tee "/home/$RDP_USER/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml" >/dev/null <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfwm4" version="1.0">
  <property name="general" type="empty">
    <property name="use_compositing" type="bool" value="false"/>
  </property>
</channel>
XML

sudo systemctl enable xrdp >/dev/null 2>&1
sudo systemctl restart xrdp

sleep 2
if ss -tlnp 2>/dev/null | grep -q ':3389'; then
    echo "RDP_READY :3389 user=$RDP_USER"
else
    echo "RDP_SETUP_FAILED -- see /tmp/rdp-apt.log"
fi
echo "=== setup-rdp done $(date -u) ==="
