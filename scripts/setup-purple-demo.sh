#!/bin/bash
# =============================================================================
# setup-purple-demo.sh -- configure a range host as a purple-team demo seat.
# =============================================================================
# Splits the 7 MCP servers into a red set (attacker) and a blue set (SOC), runs
# a Claude Code agent for each in its own tmux session, and wires the xfce
# desktop so an RDP login lands on:
#   - a terminal with two tabs, RED (aptl-red) and BLUE (the SOC tools), each
#     already at a Claude prompt, and
#   - Firefox open to the Wazuh dashboard.
#
# Prereqs on the box: the agent layer (node + claude + built MCPs), and Claude
# already onboarded for ~/aptl3 (hasCompletedOnboarding / hasTrustDialogAccepted
# in ~/.claude.json + bypass-permissions accepted) so the agents launch straight
# to a prompt without interactive dialogs. Run after the lab is provisioned.
# =============================================================================
set -uo pipefail

cd /home/ubuntu/aptl3
M=/home/ubuntu/aptl3/mcp
BEDROCK='export CLAUDE_CODE_USE_BEDROCK=1 AWS_REGION=us-east-2 ANTHROPIC_MODEL=us.anthropic.claude-sonnet-4-6 ANTHROPIC_SMALL_FAST_MODEL=us.anthropic.claude-sonnet-4-6'
RED_CMD="claude --mcp-config /home/ubuntu/aptl3/red.mcp.json --strict-mcp-config --dangerously-skip-permissions"
BLUE_CMD="claude --mcp-config /home/ubuntu/aptl3/blue.mcp.json --strict-mcp-config --dangerously-skip-permissions"

echo "=== red/blue MCP configs ==="
cat > red.mcp.json <<JSON
{"mcpServers":{
  "aptl-red":{"command":"node","args":["$M/mcp-red/build/index.js"]}
}}
JSON
cat > blue.mcp.json <<JSON
{"mcpServers":{
  "aptl-wazuh":{"command":"node","args":["$M/mcp-wazuh/build/index.js"]},
  "aptl-indexer":{"command":"node","args":["$M/mcp-indexer/build/index.js"]},
  "aptl-network":{"command":"node","args":["$M/mcp-network/build/index.js"]},
  "aptl-threatintel":{"command":"node","args":["$M/mcp-threatintel/build/index.js"]},
  "aptl-casemgmt":{"command":"node","args":["$M/mcp-casemgmt/build/index.js"]},
  "aptl-soar":{"command":"node","args":["$M/mcp-soar/build/index.js"]}
}}
JSON

echo "=== two tmux sessions: red + blue, each running a Claude ==="
tmux kill-session -t red 2>/dev/null || true
tmux kill-session -t blue 2>/dev/null || true
tmux kill-session -t purple 2>/dev/null || true
tmux new-session -d -s red -x 200 -y 50
tmux send-keys -t red "cd ~/aptl3 && $BEDROCK && clear && echo '### RED TEAM (attacker: aptl-red / kali) ###' && $RED_CMD" Enter
tmux new-session -d -s blue -x 200 -y 50
tmux send-keys -t blue "cd ~/aptl3 && $BEDROCK && clear && echo '### BLUE TEAM (SOC: wazuh/indexer/suricata/misp/thehive/shuffle) ###' && $BLUE_CMD" Enter
# clear any first-run MCP-approval prompt
sleep 16; tmux send-keys -t red Enter; tmux send-keys -t blue Enter

echo "=== xfce autostart: two-tab terminal (RED|BLUE) + Firefox -> Wazuh ==="
mkdir -p /home/ubuntu/.config/autostart
cat > /home/ubuntu/.config/autostart/purple-terminal.desktop <<'DESK'
[Desktop Entry]
Type=Application
Name=Purple Team Terminals
Exec=xfce4-terminal --maximize --tab --title=RED --command="bash -lc 'tmux attach -t red'" --tab --title=BLUE --command="bash -lc 'tmux attach -t blue'"
X-GNOME-Autostart-enabled=true
DESK
cat > /home/ubuntu/.config/autostart/wazuh.desktop <<'DESK'
[Desktop Entry]
Type=Application
Name=Wazuh Dashboard
Exec=epiphany-browser https://localhost/
X-GNOME-Autostart-enabled=true
DESK
chown -R ubuntu:ubuntu /home/ubuntu/.config/autostart

echo "PURPLE_SETUP_DONE"
