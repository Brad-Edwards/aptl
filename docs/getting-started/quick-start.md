# Quick Start

## Start Lab

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

## Access

**Wazuh Dashboard**: https://localhost:443 (admin/SecretPassword)

**SSH Access:**
```bash
# Victim
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022

# Kali
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023
```

## Test

```bash
# Generate log from victim
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022
logger "Test log entry"

# Run scan from Kali  
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023
nmap 172.20.0.20
```

View logs in Wazuh Dashboard → Security Events

## MCP Setup

```bash
# Build MCP server
cd mcp && npm install && npm run build && cd ..
```

**Configure AI client (Cursor):**
Create `.cursor/mcp.json`:
```json
{
    "mcpServers": {
        "aptl-lab": {
            "command": "node",
            "args": ["./mcp/dist/index.js"],
            "cwd": "."
        }
    }
}
```

Test with AI: "Use kali_info to show me the lab network"