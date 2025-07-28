# Kali Red Team MCP

The Model Context Protocol (MCP) server provides AI agents with controlled access to Kali tools and lab targets.

## Building the MCP Server

```bash
cd red_team/kali_mcp
npm run build
```

## Setup for AI Clients

### Cursor Setup

Create `.cursor/mcp.json` in project root:

```json
{
    "mcpServers": {
        "kali-red-team": {
            "command": "node",
            "args": ["./red_team/kali_mcp/build/index.js"],
            "cwd": "."
        }
    }
}
```

### Cline Setup

Add to Cline MCP settings:

```json
"kali-red-team": {
    "command": "node",
    "args": ["./red_team/kali_mcp/build/index.js"],
    "cwd": "<your-path-to>/aptl"
}
```

## Available MCP Tools

### `kali_info`
Get lab instance information including:
- Instance IPs and connection details
- Available tools and configurations
- Lab status and readiness

### `run_command`
Execute commands on lab targets with:
- Controlled access to Kali tools
- Target validation and safety checks
- Structured output and logging

## Usage

Connect through MCP-enabled AI clients (Claude, Cline) to:

1. **Reconnaissance**: Use tools like nmap, gobuster, enum4linux
2. **Vulnerability Assessment**: Run nikto, dirb, searchsploit
3. **Exploitation**: Execute metasploit, sqlmap, hydra
4. **Post-Exploitation**: Access shells, escalate privileges, persist

## Development Commands

```bash
cd red_team/kali_mcp

# Build the MCP server
npm run build

# Run tests
npm test
npm run test:watch

# Watch mode for development
npm run watch

# Test MCP server
npx @modelcontextprotocol/inspector build/index.js
```

## Safety Features

The MCP server includes:

- **Target Validation**: Ensures commands only target lab instances
- **Command Filtering**: Blocks dangerous system-level operations
- **Activity Logging**: Records all red team actions for analysis
- **Isolation**: Restricts access to lab environment only

This provides a safe way for AI agents to perform red team activities while maintaining proper boundaries and logging for purple team exercises.