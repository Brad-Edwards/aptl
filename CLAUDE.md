# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

APTL (Advanced Purple Team Lab) is a purple team lab infrastructure using AWS and Terraform. It deploys IBM qRadar Community Edition SIEM along with victim machines and containerized Kali Linux red team instances for security training and testing.

## Key Architecture

- **Terraform Infrastructure**: Main infrastructure defined in `infrastructure/` with modular design
  - Network module: VPC, subnets, security groups
  - SIEM module: qRadar Community Edition
  - Victim module: Target machines with log forwarding
  - Lab Container Host module: Docker host running containerized Kali red team instances
- **Red Team MCP**: TypeScript MCP server in `red_team/kali_mcp/` providing AI agents controlled access to Kali tools
- **Log Integration**: Victim machines forward logs to SIEM via rsyslog on port 514
- **qRadar SIEM**: IBM qRadar Community Edition deployment via terraform

## Development Commands

### Terraform Operations

#### Bootstrap Infrastructure (Required First)

```bash
cd infrastructure/bootstrap
terraform init
terraform apply
./create_backend.sh     # Creates backend.tf with UUID bucket name
terraform init -migrate-state   # Migrates state to S3
```

#### Main Infrastructure

```bash
cd infrastructure
terraform init
terraform apply
./create_backend.sh     # Creates backend.tf with UUID bucket name  
terraform init -migrate-state   # Migrates state to S3
```

#### Cleanup

```bash
# Destroy main infrastructure first
cd infrastructure
terraform destroy

# Then destroy bootstrap
cd bootstrap  
terraform destroy
```

### Containerized Kali Development

```bash
# Build Kali container image
cd containers/kali
docker build -t aptl-kali .

# Push to registry (if using ECR)
docker tag aptl-kali:latest <account>.dkr.ecr.us-east-1.amazonaws.com/aptl-kali:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/aptl-kali:latest

# Build MCP server for container integration
cd red_team/kali_mcp
npm run build
npm test
npm run watch  # Development mode

# Test MCP server
npx @modelcontextprotocol/inspector build/index.js
```

## Configuration

### Primary Configuration

- **terraform.tfvars**: Main configuration file (copy from terraform.tfvars.example)
  - Uses `siem_type = "qradar"` (default configuration)
  - Configure `allowed_ip` to your IP in CIDR notation
  - Set instance types and deployment flags (`enable_siem`, `enable_victim`, `enable_lab_container_host`)

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

### CRITICAL: Terraform Commands

- **NEVER EVER run terraform apply, terraform destroy, terraform plan, or any terraform command**
- Only suggest commands for the user to run themselves
- This is a strict rule with no exceptions

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

### Testing Containerized Red Team Integration

1. Build Kali container: `cd containers/kali && docker build -t aptl-kali .`
2. Build MCP server: `cd red_team/kali_mcp && npm run build`
3. Deploy infrastructure with `enable_lab_container_host = true`
4. Configure MCP client (Cursor/Cline) to connect to container host
5. Test with AI agents using `kali_info` and `run_command` tools

### Verifying SIEM Integration

1. Check lab_connections.txt for connection details
2. SSH to containerized Kali instance via container host
3. SSH to victim machine and run test event generators
4. Verify logs appear in SIEM with proper routing/indexing

## Troubleshooting

Key log locations:

- Instance setup: `/var/log/user-data.log`
- Container logs: `docker logs <container_id>`
- Container host setup: `/var/log/user-data.log` on container host
- Log forwarding: `journalctl -u rsyslog -f`
- Network connectivity: Test port 514 between victim and SIEM

See troubleshooting.md for detailed debugging procedures.
