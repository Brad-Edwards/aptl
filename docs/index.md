# APTL

Local Docker-based purple team lab. AI agents conduct attacks and defensive analysis via MCP integration with Wazuh SIEM and Kali Linux containers.

## Core Components

- **Wazuh SIEM** — Manager, Indexer, Dashboard for log collection and alerting
- **Victim container** — Rocky Linux target with Wazuh agent and Falco eBPF monitoring
- **Kali container** — Attack platform, all commands logged to SIEM
- **Reverse engineering container** — Binary analysis tools
- **MCP servers** — AI agent control of lab containers and SIEM APIs

Optional enterprise and SOC containers are available via Docker Compose profiles.

## Get Started

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

See [Getting Started](getting-started/) for prerequisites and detailed setup.

## Access

| Service | Address | Credentials |
|---------|---------|-------------|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| Victim SSH | localhost:2022 | labadmin / aptl_lab_key |
| Kali SSH | localhost:2023 | kali / aptl_lab_key |
| Reverse SSH | localhost:2027 | labadmin / aptl_lab_key |

## Documentation

- [Getting Started](getting-started/) — Prerequisites, installation, quick start
- [Architecture](architecture/) — Network topology, container layout
- [Components](components/) — Wazuh, victim, Kali, MCP servers
- [Scenarios](usage/scenarios.md) — Scenario engine and examples
- [CLI Reference](reference/cli.md) — All CLI commands
- [Deployment](deployment.md) — Manual deployment and configuration
- [Troubleshooting](troubleshooting/) — Common issues and fixes
