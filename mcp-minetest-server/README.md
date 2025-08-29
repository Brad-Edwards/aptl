# MCP Minetest Server

MCP server for AI agent control of Minetest server container.

## Tools

- `container_info` - Get minetest-server container info
- `run_command` - Execute commands on minetest-server container

## Quick Setup

### 1. Build the MCP Server

```bash
# From the APTL root directory
cd mcp
npm install
npm run build
```

### 2. Start the Lab

```bash
# Make sure the Docker lab is running first
cd ..
./start-lab.sh
```

### 3. Configure Your AI Client

Choose your AI client and add the MCP configuration:

#### For Cursor IDE

Create `.cursor/mcp.json` in the APTL project root:

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

#### For Cline (VS Code)

Add to your Cline MCP settings:

```json
{
    "aptl-lab": {
        "command": "node",
        "args": ["./mcp/dist/index.js"],
        "cwd": "/path/to/your/aptl"
    }
}
```

#### For Claude Desktop

Add to your Claude Desktop MCP configuration:

```json
{
    "mcpServers": {
        "aptl-lab": {
            "command": "node",
            "args": ["./mcp/dist/index.js"],
            "cwd": "/path/to/your/aptl"
        }
    }
}
```

### 4. Test the Connection

After configuring your AI client, test that it can see the APTL tools:

1. Ask your AI: "What MCP tools do you have available?"
2. You should see `kali_info` and `run_command` tools listed
3. Try: "Use kali_info to show me the lab network information"

## Prerequisites

- ✅ **Docker Lab Running**: APTL lab must be started with `./start-lab.sh`
- ✅ **SSH Keys Generated**: Lab startup script creates `~/.ssh/aptl_lab_key`
- ✅ **Node.js**: Version 18+ for MCP server
- ✅ **AI Client**: Cursor, Cline, Claude Desktop, or other MCP-compatible client

## Verification Steps

### 1. Verify Lab is Running

```bash
# Check containers are up
docker compose ps

# Should show all containers running:
# - aptl-kali
# - aptl-victim  
# - wazuh.manager
# - wazuh.dashboard
# - wazuh.indexer
```

### 2. Verify SSH Access

```bash
# Test manual SSH to both containers
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 "echo 'Kali OK'"
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 "echo 'Victim OK'"
```

### 3. Verify MCP Server

```bash
# Test MCP server directly
cd mcp
node dist/index.js
# Should start without errors
```

### 4. Test with AI Agent

Ask your AI agent to:
1. "Get lab information using kali_info"
2. "Run a simple network scan: nmap -sn 172.20.0.0/24"
3. "Show me what services are running on the victim at 172.20.0.20"

## Example AI Workflows

Once set up, AI agents can autonomously perform red team operations:

### Network Reconnaissance

```
AI Agent: I'll start by gathering information about the lab network.

Using kali_info tool to get network topology...

Network discovered:
- Victim: 172.20.0.20 (SSH, HTTP, FTP)
- Wazuh SIEM: 172.20.0.10
- Kali Platform: 172.20.0.30

Now scanning the victim system...

Using run_command: nmap -sV -sC 172.20.0.20
```

### Vulnerability Assessment

```
AI Agent: Based on the port scan, I found several services. Let me enumerate them further.

Using run_command: gobuster dir -u http://172.20.0.20 -w /usr/share/wordlists/common.txt

Found /admin directory. Testing for weak authentication...

Using run_command: hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://172.20.0.20
```

### Autonomous Purple Team Exercise

```
AI Agent: I'll demonstrate an autonomous attack while you monitor in Wazuh.

1. Network reconnaissance - Completed
2. Service enumeration - In progress
3. Vulnerability exploitation - Planned
4. Post-exploitation - Planned

Check your Wazuh Dashboard at https://localhost:443 to see the attack in real-time!
```

## Configuration

### Lab Configuration

The MCP server reads from `docker-lab-config.json`:

```json
{
  "lab": {
    "containers": {
      "kali": {
        "ip": "172.20.0.30",
        "ssh_port": 2023,
        "ssh_user": "kali"
      },
      "victim": {
        "ip": "172.20.0.20",
        "ssh_port": 2022,
        "ssh_user": "labadmin"
      }
    }
  },
  "ssh": {
    "key_path": "~/.ssh/aptl_lab_key",
    "timeout": 10000
  },
  "safety": {
    "allowed_networks": ["172.20.0.0/16"],
    "rate_limit": 30
  }
}
```

### Environment Variables

```bash
# Optional environment variables
export APTL_LOG_LEVEL=info
export APTL_SSH_KEY_PATH=~/.ssh/aptl_lab_key
export APTL_LAB_NETWORK=172.20.0.0/16
```

## Safety Features

The MCP server includes multiple safety controls:

- **Network Restrictions**: Commands only allowed against lab network (172.20.0.0/16)
- **Command Validation**: Dangerous commands are blocked or sanitized
- **Rate Limiting**: Prevents excessive command execution
- **Audit Logging**: All AI actions logged for review
- **SSH Key Validation**: Uses specific lab SSH keys only

## Troubleshooting

### Common Issues

1. **"No MCP tools available"**
   ```bash
   # Check MCP server builds correctly
   cd mcp && npm run build
   
   # Verify configuration path in AI client
   # Should point to ./mcp/dist/index.js
   ```

2. **"SSH connection failed"**
   ```bash
   # Verify containers are running
   docker compose ps
   
   # Test SSH manually
   ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023
   ```

3. **"Command validation failed"**
   - AI tried to target external IP (blocked for safety)
   - Command contains dangerous patterns (blocked for safety)
   - Check logs: `tail -f mcp/logs/activity.log`

4. **"MCP server won't start"**
   ```bash
   # Check Node.js version
   node --version  # Should be 18+
   
   # Rebuild server
   cd mcp && npm run clean && npm run build
   ```

### Debug Mode

```bash
# Run MCP server with debug logging
cd mcp
DEBUG=* node dist/index.js

# Or use the built-in inspector
npm run inspector
```

### Log Analysis

```bash
# View MCP activity logs
tail -f mcp/logs/mcp-activity.log

# View SSH connection logs
tail -f mcp/logs/ssh-debug.log
```

## Development

### Building and Testing

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run tests
npm run test

# Watch mode for development
npm run watch

# Type checking
npm run type-check
```

### Adding Custom Tools

Extend the MCP server by adding tools in `src/index.ts`:

```typescript
{
  name: "custom_scan",
  description: "Execute custom security scan",
  inputSchema: {
    type: "object", 
    properties: {
      target: { type: "string" },
      scan_type: { type: "string", enum: ["fast", "full", "vuln"] }
    }
  }
}
```

## Security Considerations

- **Isolated Environment**: All commands execute within Docker lab network
- **No External Access**: AI cannot target systems outside 172.20.0.0/16
- **Audit Trail**: Complete logging of all AI actions
- **Rate Limited**: Prevents resource exhaustion
- **Easy Reset**: Lab can be completely reset if needed

## Best Practices

1. **Always Start Lab First**: Ensure Docker containers are running before using MCP
2. **Monitor AI Actions**: Watch Wazuh Dashboard during AI operations
3. **Review Logs**: Regular review of AI decision-making and actions
4. **Set Clear Objectives**: Give AI agents specific, bounded objectives
5. **Understand Capabilities**: Review what tools are available to AI agents

## Getting Help

If you're having issues:

1. **Check Prerequisites**: Verify Docker lab is running and SSH keys exist
2. **Test Manual SSH**: Ensure you can SSH to containers manually
3. **Review Logs**: Check MCP server logs for error messages
4. **Validate Configuration**: Ensure AI client MCP config points to correct paths
5. **Restart Components**: Try restarting lab and rebuilding MCP server

## Next Steps

Once MCP is working:

- **[AI Red Teaming Guide](../docs/usage/ai-red-teaming.md)** - Advanced AI attack scenarios
- **[Purple Team Exercises](../docs/usage/exercises.md)** - Structured training scenarios  
- **[Component Documentation](../docs/components/mcp-integration.md)** - Technical MCP details