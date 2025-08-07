# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

APTL (Advanced Purple Team Lab) is a local Docker-based purple team lab infrastructure. It deploys Wazuh SIEM stack along with containerized victim machines and Kali Linux red team instances for security training and testing.

## Key Architecture

- **Docker Compose Infrastructure**: Complete lab environment defined in `docker-compose.yml`
  - Wazuh Manager: SIEM backend and API (172.20.0.10)
  - Wazuh Indexer: OpenSearch-based data storage (172.20.0.12)
  - Wazuh Dashboard: Web interface (172.20.0.11)
  - Victim Container: Target machine with services (172.20.0.20)
  - Kali Container: Red team platform (172.20.0.30)
- **Red Team MCP**: TypeScript MCP server in `mcp/` providing AI agents controlled access to lab containers
- **Log Integration**: Victim containers forward logs to Wazuh Manager via rsyslog on port 514
- **Container Network**: Isolated Docker network (172.20.0.0/16) for all lab communications

## Development Commands

### Lab Operations

#### Start Complete Lab

```bash
# Start entire lab environment (recommended)
./start-lab.sh
```

#### Manual Docker Operations

```bash
# Start lab manually
docker compose up -d

# View service logs
docker compose logs -f [service_name]

# Stop lab
docker compose down

# Cleanup (removes all data)
docker compose down -v

# Restart specific service
docker compose restart [service_name]
```

#### Container Development

```bash
# Build Kali container image
cd containers/kali
docker build -t aptl-kali .

# Build victim container image
cd containers/victim
docker build -t aptl-victim .

# Build MCP server
cd mcp
npm run build
npm test
npm run watch  # Development mode

# Test MCP server
npx @modelcontextprotocol/inspector dist/index.js
```

## Configuration

### Primary Configuration

- **docker-compose.yml**: Main lab environment configuration
- **config/**: Wazuh configuration files
  - `wazuh_cluster/wazuh_manager.conf`: Manager configuration
  - `wazuh_dashboard/`: Dashboard and UI configuration
  - `wazuh_indexer/`: OpenSearch indexer configuration
- **Environment Variables**: Container-specific settings in docker-compose.yml

### MCP Server Setup

For AI agents to access lab containers via MCP:

**Cursor**: Create `.cursor/mcp.json`:

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

**Cline**: Add to MCP settings:

```json
"aptl-lab": {
    "command": "node",
    "args": ["./mcp/dist/index.js"],
    "cwd": "/path/to/aptl"
}
```

## Important Notes

### CRITICAL: Docker Operations

- **Use `./start-lab.sh` for initial setup** - handles all prerequisites and startup
- **Use `docker compose` commands for manual operations** when needed
- **Always check container status** with `docker compose ps` before troubleshooting

### Security Context

- This is a legitimate security research and training lab
- All attacks are contained within the lab environment
- Victim machines are purpose-built targets for testing
- Red team logging helps track attack activities for analysis

### Wazuh Features

- **Red Team Logging**: Custom rules for red team activity classification
- **Log Sources**: Container-based log routing for attack separation
- **Custom Fields**: RedTeamActivity, RedTeamCommand, RedTeamTarget metadata
- **Real-time Monitoring**: Live dashboard showing attack progression

### System Requirements

- **Docker**: Docker Engine and Docker Compose
- **System**: 8GB+ RAM, 20GB+ disk space
- **Ports**: 443, 2022, 2023, 9200, 55000 must be available
- **OS**: Linux, macOS, or Windows with WSL2

### Startup Timing

- Container startup: 2-3 minutes
- Wazuh Indexer initialization: 3-5 minutes
- Complete lab ready: 5-10 minutes
- SSH services available: 1-2 minutes after startup

## Common Development Workflows

### Starting the Lab

1. Clone repository and navigate to directory
2. Run `./start-lab.sh` (handles all setup automatically)
3. Wait for all services to become ready
4. Access services via connection details in `lab_connections.txt`

### Testing Red Team Integration

1. Start lab: `./start-lab.sh`
2. Build MCP server: `cd mcp && npm run build`
3. Configure MCP client (Cursor/Cline) with local container configuration
4. Test with AI agents using `kali_info` and `run_command` tools
5. Verify container connectivity: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

### Verifying SIEM Integration

1. Access Wazuh Dashboard: <https://localhost:443> (admin/SecretPassword)
2. SSH to victim container: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
3. Generate test logs: `logger "Test message from victim"`
4. Verify logs appear in Wazuh with proper indexing and routing
5. Check red team logging from Kali container activities

## Troubleshooting

Key troubleshooting commands:

- Container status: `docker compose ps`
- Service logs: `docker compose logs -f [service]`
- Container shell access: `docker exec -it [container] /bin/bash`
- Network connectivity: `docker network inspect aptl_aptl-network`
- Port connectivity: `netstat -tlnp | grep [port]`
- Log forwarding test: `docker exec aptl-victim logger "Test message"`

Common log locations in containers:
- Wazuh Manager: `docker compose logs wazuh.manager`
- Victim logs: `docker compose logs victim`
- Kali operations: `docker exec aptl-kali cat /home/kali/operations/activity.log`

See docs/troubleshooting/ for detailed debugging procedures.
