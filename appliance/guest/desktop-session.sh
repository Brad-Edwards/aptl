#!/bin/sh
# XFCE autostart for the participant account. Agent sign-in stays in its home.
set -eu
cd /opt/aptl/project
# Direct host and LAN access stays blocked. The per-seat forward accepts public
# HTTPS connections for Claude sign-in and browsing.
export HTTP_PROXY=http://10.0.2.100:3128
export HTTPS_PROXY=$HTTP_PROXY
export http_proxy=$HTTP_PROXY
export https_proxy=$HTTP_PROXY
export NO_PROXY=localhost,127.0.0.1,10.0.2.15,host.docker.internal
export no_proxy=$NO_PROXY
export CLAUDE_CODE_PROXY_RESOLVES_HOSTS=1
if command -v gsettings >/dev/null 2>&1 && \
        gsettings list-schemas | grep -qx org.gnome.system.proxy; then
    gsettings set org.gnome.system.proxy mode manual
    gsettings set org.gnome.system.proxy.http host 10.0.2.100
    gsettings set org.gnome.system.proxy.http port 3128
    gsettings set org.gnome.system.proxy.https host 10.0.2.100
    gsettings set org.gnome.system.proxy.https port 3128
    gsettings set org.gnome.system.proxy ignore-hosts \
        "['localhost', '127.0.0.1', '10.0.2.15', 'host.docker.internal']"
fi
for role in red blue; do
    if ! tmux has-session -t "$role" 2>/dev/null; then
        tmux new-session -d -s "$role" \
            "printf 'Starting the lab. Claude will open when services are ready.\\n'; while test ! -f /home/aptl/.config/aptl/run-ready; do sleep 2; done; cd /opt/aptl/project && /usr/local/bin/claude --mcp-config /home/aptl/$role.mcp.json --strict-mcp-config --dangerously-skip-permissions; exec sh"
    fi
done
epiphany about:blank &
sleep 3
xfce4-terminal --maximize \
    --title=RED --command='tmux attach -t red' \
    --tab --title=BLUE --command='tmux attach -t blue' &
wait
