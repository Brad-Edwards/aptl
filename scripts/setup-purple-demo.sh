set -uo pipefail
cd /home/ubuntu/aptl3
M=/home/ubuntu/aptl3/mcp
BEDROCK='export CLAUDE_CODE_USE_BEDROCK=1 AWS_REGION=us-east-2 ANTHROPIC_MODEL=us.anthropic.claude-sonnet-4-6 ANTHROPIC_SMALL_FAST_MODEL=us.anthropic.claude-sonnet-4-6'

echo "=== write red/blue MCP configs ==="
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
echo "red: $(python3 -c 'import json;print(list(json.load(open("red.mcp.json"))["mcpServers"]))')"
echo "blue: $(python3 -c 'import json;print(list(json.load(open("blue.mcp.json"))["mcpServers"]))')"

echo "=== (re)create tmux session 'purple' with red + blue Claude windows ==="
tmux kill-session -t purple 2>/dev/null || true
tmux new-session -d -s purple -n red -x 220 -y 50
tmux send-keys -t purple:red "cd ~/aptl3 && $BEDROCK && clear && echo '### RED TEAM (attacker: aptl-red / kali) ###' && claude --mcp-config ~/aptl3/red.mcp.json --dangerously-skip-permissions" Enter
tmux new-window -t purple -n blue
tmux send-keys -t purple:blue "cd ~/aptl3 && $BEDROCK && clear && echo '### BLUE TEAM (SOC: wazuh/indexer/suricata/misp/thehive/shuffle) ###' && claude --mcp-config ~/aptl3/blue.mcp.json --dangerously-skip-permissions" Enter
tmux select-window -t purple:red
echo "tmux sessions:"; tmux ls

echo "=== xfce autostart: Firefox -> Wazuh; + terminal attaching tmux 'purple' ==="
mkdir -p /home/ubuntu/.config/autostart
cat > /home/ubuntu/.config/autostart/wazuh.desktop <<DESK
[Desktop Entry]
Type=Application
Name=Wazuh Dashboard
Exec=firefox https://localhost/
X-GNOME-Autostart-enabled=true
DESK
cat > /home/ubuntu/.config/autostart/purple-terminal.desktop <<DESK
[Desktop Entry]
Type=Application
Name=Purple Team Terminals
Exec=xfce4-terminal --maximize --title="APTL Purple (red|blue)" -e "bash -lc 'tmux attach -t purple'"
X-GNOME-Autostart-enabled=true
DESK
chown -R ubuntu:ubuntu /home/ubuntu/.config/autostart

echo "DEMO_SETUP_DONE"
