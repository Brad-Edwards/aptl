# APTL (Advanced Purple Team Lab)

Local Docker-based purple team lab. AI agents conduct attacks and defensive analysis via MCP integration with Wazuh SIEM and Kali Linux containers.

> **Not for production use.** This is a security research and training lab. Monitor AI agents closely during scenarios.

## Components

| Component | Role |
|-----------|------|
| Wazuh SIEM (Manager, Indexer, Dashboard) | Log collection, analysis, alerting |
| Victim container (Rocky Linux) | Target system with Wazuh agent + Falco eBPF monitoring |
| Kali container | Attack platform, logs red team commands to SIEM |
| Reverse engineering container | Binary analysis tools |
| MCP servers | AI agent control of Kali, Wazuh, and reverse engineering containers |

Optional enterprise containers (AD, webapp, database, mail, DNS, fileshare) and SOC tools (MISP, TheHive, Shuffle, Cortex) are available via Docker Compose profiles.

## Quick Start

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

Alternative: `./start-lab.sh`

Both handle SSH keys, SSL certificates, system checks, and container startup.

## Lab Management

```bash
aptl lab status   # Show running containers and health
aptl lab stop     # Stop the lab
aptl lab stop -v  # Stop and remove all volumes
```

## Access

| Service | Address | Credentials |
|---------|---------|-------------|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| Wazuh API | https://localhost:55000 | wazuh-wui / WazuhPass123! |
| Indexer API | https://localhost:9200 | admin / SecretPassword |
| Victim SSH | `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022` | key auth |
| Kali SSH | `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023` | key auth |
| Reverse SSH | `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027` | key auth |

## Requirements

- Docker + Docker Compose
- Python 3.11+ (for CLI)
- 8GB+ RAM, 20GB+ disk
- Linux, macOS, or Windows with WSL2
- Ports: 443, 2022, 2023, 2027, 9200, 55000

Linux/WSL2 requires `vm.max_map_count >= 262144` for OpenSearch. See [Prerequisites](docs/getting-started/prerequisites.md).

## MCP Integration

MCP servers are built automatically by `aptl lab start`. To build manually:

```bash
./mcp/build-all-mcps.sh
```

Configure your MCP client (Cursor, Cline, etc.) to point at the built servers:

| Server | Entry point | Tool prefix |
|--------|-------------|-------------|
| Red Team (Kali) | `mcp/mcp-red/build/index.js` | `kali_*` |
| Blue Team (Wazuh) | `mcp/mcp-wazuh/build/index.js` | `wazuh_*` |
| Reverse Engineering | `mcp/mcp-reverse/build/index.js` | `reverse_*` |

Additional MCP servers exist for threat intel, case management, SOAR, network IDS, and Windows RE. See [MCP Integration](docs/components/mcp-integration.md).

## Scenarios

APTL includes a scenario engine with scored objectives, time bonuses, and progressive hints.

```bash
aptl scenario list            # List available scenarios
aptl scenario start <name>    # Start a scenario
aptl scenario status          # Check progress
aptl scenario evaluate        # Score objectives
aptl scenario hint <id>       # Get a hint
aptl scenario stop            # End scenario
```

See [Scenarios](docs/usage/scenarios.md) for details.

## Documentation

- [Getting Started](docs/getting-started/) — Prerequisites, installation, quick start
- [Architecture](docs/architecture/) — Network topology, container layout
- [Components](docs/components/) — Wazuh, victim, Kali, MCP servers
- [Scenarios](docs/usage/scenarios.md) — Scenario engine and examples
- [CLI Reference](docs/reference/cli.md) — All CLI commands
- [Troubleshooting](docs/troubleshooting/) — Common issues and fixes

## Security

- This lab gives AI agents access to real penetration testing tools. Always monitor agents during scenarios.
- No guarantees about container isolation or escape prevention.
- Docker networking may not prevent all forms of network access.
- You are responsible for following all applicable laws.
- The author takes no responsibility for your use of this lab.

## Test Credentials

This repository contains intentional test credentials for lab functionality. All are dummy values for educational use, covered by the GitGuardian whitelist (`.gitguardian.yaml`). The environment contains vulnerable configurations by design.

## Ethics

This lab uses consumer-grade, commodity services and basic integrations that do not advance existing offensive capabilities. No enhancements are made to AI agents beyond Kali container access. No red-team enhancements will be added to this public repository.

## License

MIT
