# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

APTL (Advanced Purple Team Lab) is a purple team lab infrastructure using AWS and Terraform. It deploys IBM qRadar Community Edition SIEM along with victim machines and Kali Linux red team instances for security training and testing.

## Key Architecture

- **Terraform Infrastructure**: Main infrastructure defined in `infrastructure/` with modular design
  - Network module: VPC, subnets, security groups
  - SIEM module: qRadar Community Edition
  - Victim module: Target machines with log forwarding
  - Kali module: Red team instances with attack tools
- **Red Team MCP**: TypeScript MCP server in `red_team/kali_mcp/` providing AI agents controlled access to Kali tools
- **Log Integration**: Victim machines forward logs to SIEM via rsyslog on port 514
- **qRadar SIEM**: IBM qRadar Community Edition deployment via terraform

## Development Commands

### Terraform Operations
```bash
# Initialize and deploy infrastructure
terraform init
terraform plan
terraform apply

# Clean up all resources
terraform destroy
```

### Kali MCP Development
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

## Configuration

### Primary Configuration
- **terraform.tfvars**: Main configuration file (copy from terraform.tfvars.example)
  - Uses `siem_type = "qradar"` (default configuration)
  - Configure `allowed_ip` to your IP in CIDR notation
  - Set instance types and deployment flags (`enable_siem`, `enable_victim`, `enable_kali`)

### MCP Server Setup
For AI agents to access Kali tools via MCP:

**Cursor**: Create `.cursor/mcp.json`:
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

## Important Notes

### Security Context
- This is a legitimate security research and training lab
- All attacks are contained within the lab environment
- Victim machines are purpose-built targets for testing
- Red team logging helps track attack activities for analysis

### qRadar Features
- **Red Team Logging**: Custom properties for red team activity classification
- **Log Sources**: Dedicated "APTL-Kali-RedTeam" log source for attack separation
- **Custom Properties**: RedTeamActivity, RedTeamCommand, RedTeamTarget fields

### File Requirements
- **qRadar**: Requires ISO file and license key in `files/` directory

### Instance Timing
- Infrastructure deployment: 3-5 minutes
- Instance configuration via user_data: 10-20 minutes per instance
- qRadar installation: 1-2 hours

## Common Development Workflows

### Deploying Lab Infrastructure
1. Copy and configure terraform.tfvars.example
2. Place qRadar ISO and license files in `files/`
3. Run `terraform apply`
4. Monitor instance setup via SSH and log files

### Testing Red Team MCP Integration
1. Build MCP server: `cd red_team/kali_mcp && npm run build`
2. Configure MCP client (Cursor/Cline)
3. Test with AI agents using `kali_info` and `run_command` tools

### Verifying SIEM Integration
1. Check lab_connections.txt for connection details
2. SSH to victim machine and run test event generators
3. Verify logs appear in SIEM with proper routing/indexing

## Troubleshooting

Key log locations:
- Instance setup: `/var/log/user-data.log`
- Log forwarding: `journalctl -u rsyslog -f`
- Network connectivity: Test port 514 between victim and SIEM

See troubleshooting.md for detailed debugging procedures.