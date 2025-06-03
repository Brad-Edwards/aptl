# APTL Kali MCP Server

Model Context Protocol server for APTL Kali Linux red team operations.

Provides AI agents with secure access to lab instances via SSH.

## Tools

- `kali_info` - Get lab instance information  
- `run_command` - Execute commands on lab targets

## Setup

Build the server:

```bash
npm install
npm run build
```

**Cursor** - Create `.cursor/mcp.json` in project root:

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

**Cline** - Add to MCP settings:

```json
"kali-red-team": {
    "command": "node",
    "args": ["./red_team/kali_mcp/build/index.js"],
    "cwd": "<your-path-to>/aptl"
}
```

## Prerequisites

- Deployed APTL lab (`terraform apply`)
- SSH keys matching `terraform.tfvars` configuration
- Terraform available in PATH

## Development

```bash
npm run watch    # Auto-rebuild on changes
npm run test     # Run test suite
npm run inspector # Debug with MCP Inspector
```

## How it works

1. Reads lab config from `terraform output`
2. Auto-detects SSH credentials per target IP
3. Executes commands via SSH with connection pooling
4. Validates targets against allowed lab networks

## Security

- Commands restricted to lab CIDR ranges only
- Uses actual SSH keys from Terraform configuration  
- All operations logged for audit
