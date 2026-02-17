#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Building APTL MCP Servers ==="

# Build shared dependency first
echo "--- Building aptl-mcp-common (shared dependency) ---"
cd "$SCRIPT_DIR/aptl-mcp-common" && npm install && npm run build

# Build all MCP servers
for server in mcp-red mcp-wazuh mcp-reverse mcp-windows-re mcp-threatintel mcp-casemgmt mcp-soar mcp-network; do
  echo "--- Building $server ---"
  cd "$SCRIPT_DIR/$server" && npm install && npm run build
done

echo "=== All MCP servers built successfully ==="
