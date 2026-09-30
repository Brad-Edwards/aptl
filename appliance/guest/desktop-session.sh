#!/bin/sh
# XFCE autostart for the participant account. Agent sign-in stays in its home.
set -eu
cd /opt/aptl/project
if command -v gsettings >/dev/null 2>&1 && \
        gsettings list-schemas | grep -qx org.gnome.system.proxy; then
    gsettings set org.gnome.system.proxy mode none
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
