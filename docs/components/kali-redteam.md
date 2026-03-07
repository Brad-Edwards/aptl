# Kali Red Team Container

The Kali Linux container provides a platform for AI agents to execute security tools via MCP integration.

## Container Configuration

- **Base Image**: kalilinux/kali-last-release:latest
- **Tools**: kali-linux-core, kali-tools-top10
- **User**: `kali` with sudo privileges
- **SSH**: Key-based authentication only (port 22, mapped to host 2023)

See [containers/kali/Dockerfile](../../containers/kali/Dockerfile) for complete build configuration.

## Network Access

- **Container IPs**: 172.20.4.30 (redteam), 172.20.1.30 (dmz), 172.20.2.35 (internal)
- **Networks**: aptl-redteam, aptl-dmz, aptl-internal
- **Target Access**: DMZ (webapp 172.20.1.20, mail 172.20.1.21, DNS 172.20.1.22) and internal (AD 172.20.2.10, DB 172.20.2.11, victim 172.20.2.20)
- **SSH Access**: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## MCP Integration

### Red Team MCP Server

The MCP server enables AI agents to control Kali tools remotely:

**Available Tools:**

- `kali_info`: Display lab network information
- `run_command`: Execute commands on Kali container

**Setup:**

```json
{
    "mcpServers": {
        "aptl-lab": {
            "command": "node",
            "args": ["./mcp/mcp-red/build/index.js"],
            "cwd": "."
        }
    }
}
```

**Usage:**

```bash
# Build MCP server
cd mcp/mcp-red && npm install && npm run build

# Test connection
npx @modelcontextprotocol/inspector build/index.js
```

See [MCP Integration](mcp-integration.md) for detailed setup instructions.

## SIEM Integration

Red team activities are logged to Wazuh SIEM via Wazuh agent:

- **Agent Group**: `kali-redteam`
- **Logs**: CLI commands, authentication events, system logs
- **Destination**: Wazuh Manager (172.20.0.10:1514)
- **Purpose**: Blue team analysis and detection training

## Access

```bash
# SSH access
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023
```
