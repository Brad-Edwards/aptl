[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=Brad-Edwards_aptl&token=4dd88be3421d6d030a4615b86ac8ab0e3c9eb4d3)](https://sonarcloud.io/summary/new_code?id=Brad-Edwards_aptl)

🎤 **Accepted to [Black Hat USA Arsenal 2026](https://blackhat.com/us-26/arsenal/schedule/#aptl-advanced-purple-team-labs-52322).** Live demo at the conference.

# APTL — Advanced Purple Team Lab

**Purple-team lab where AI agents drive the red and blue sides against an enterprise target stack.**

One `aptl lab start` brings up: a fictional company's infrastructure (AD, web, DB, file share, DNS, mail), a Kali red-team box, a SOC stack (Wazuh + Suricata + MISP + TheHive + Cortex + Shuffle), a malware-analysis container, and MCP servers giving AI agents programmatic control over all of it. Scenarios are YAML-defined; each run captures a telemetry archive.

**Use cases:** autonomous cyber-operations research, purple-team training, AI threat-actor assessment.

## Status

**🚧 Active development. Not for production. Not hardened.** This lab gives AI agents access to real penetration-testing tools and runs intentionally vulnerable services. Container escapes and other security issues are possible — keep it on a host you can rebuild and a network you control. Always monitor red-team agents during scenarios.

## Quick Start

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

Once it's up:

| Surface | URL / command |
|---|---|
| Wazuh Dashboard | <https://localhost:443> (`admin` / `SecretPassword`) |
| Victim SSH | `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022` |
| Kali SSH | `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023` |
| Reverse engineering SSH | `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027` |

Lifecycle:

```bash
aptl lab status   # running containers
aptl lab stop     # graceful stop
aptl lab stop -v  # ⚠ destroys all lab data (Wazuh indexes, MISP, TheHive, configs)
aptl kill         # emergency: kill MCP server processes
aptl kill -c      # emergency: kill MCP processes AND all lab containers
```

## Requirements

- Docker + Docker Compose
- Python 3.11+
- 8 GB RAM, 20 GB disk
- Linux / macOS / WSL2
- Open ports: 443, 2022, 2023, 2027, 9200, 55000

## Architecture

```
┌──── Red Team (172.20.4.0/24) ─┐   ┌──── DMZ (172.20.1.0/24) ──────────────┐
│  Kali (.30)                    │──>│  Web App (.20/.25)   Mail (.21)        │
│  pentest tools, MCP-controlled │   │  DNS (.22)                             │
└────────────────────────────────┘   └──────────────┬────────────────────────-┘
                                                    │ pivot
                                     ┌──── Internal (172.20.2.0/24) ─────────┐
                                     │  Samba AD DC (.10)  PostgreSQL (.11)   │
                                     │  File Server (.12)  Victim (.20)       │
                                     └──────────────┬────────────────────────-┘
                                                    │ logs
┌──── Security (172.20.0.0/24) ──────────────────────────────────────────────┐
│  Wazuh Manager (.10)  Indexer (.12)  Dashboard (.11)                       │
│  Suricata IDS (.50)   MISP (.16)     TheHive (.18) + Cortex (.22)         │
│  Shuffle SOAR (.20/.21)              Reverse Engineering (.27)             │
└──────────────────────────────────┬─────────────────────────────────────────┘
                                   │
┌──── MCP Server Layer ────────────────────────────────────────────────────-─┐
│  mcp-red       mcp-wazuh      mcp-indexer     mcp-network                  │
│  mcp-reverse   mcp-casemgmt   mcp-soar        mcp-threatintel              │
└──────────────────────────────────┬─────────────────────────────────────────┘
                                   │
                              AI Agents
```

Component-by-component breakdown: [docs/architecture/index.md](docs/architecture/index.md).

## AI Agents (MCP)

Build the MCP servers:

```bash
./mcp/build-all-mcps.sh
```

Point your AI client (Claude Code, Cursor, Cline) at the entry points under `./mcp/<server>/build/index.js`. Full setup: [MCP Integration](docs/components/mcp-integration.md).

Smoke-test the wiring once the lab is up:

- Red side: ask the agent *"Use kali_info to show me the lab network"*
- Blue side: ask the agent *"Use wazuh_query_alerts to show me recent alerts"*

## Optional: Web UI

Localhost-only web UI for lab control and scenario runs.

```bash
pip install -e ".[web]"
aptl web serve                 # API server
cd web && npm install && npm run dev   # frontend (separate terminal)
```

Access at <http://localhost:5173> (dev) or <http://localhost:3000> (prod). The API container needs the host Docker socket; do not expose to untrusted networks.

## Documentation

**Getting started:** [Installation](docs/getting-started/installation.md) · [Prerequisites](docs/getting-started/prerequisites.md) · [Quick Start Guide](docs/getting-started/quick-start.md)

**Architecture:** [Overview](docs/architecture/index.md) · [Networking](docs/architecture/networking.md) · [Enterprise Infrastructure](docs/architecture/enterprise-infrastructure.md)

**Components:** [Wazuh SIEM](docs/components/wazuh-siem.md) · [Kali Red Team](docs/components/kali-redteam.md) · [Victim Containers](docs/components/victim-containers.md) · [Reverse Engineering](docs/components/reverse-engineering-container.md) · [MCP Integration](docs/components/mcp-integration.md) · [Default Defensive Posture](docs/components/default-defensive-posture.md)

**Scenarios & runs:** [SOC Architecture Spec](docs/specs/soc-feature-spec.md)

**Reference:** [TechVault Company Profile](docs/reference/techvault-company-profile.md) · [TechVault OSINT Readiness](docs/reference/techvault-osint-readiness.md) · [Container Template Guide](docs/containers/victim-template-guide.md)

**Ops:** [Troubleshooting](docs/troubleshooting/) · [Known Issues](docs/known-issues/uat-findings-2026-02-23.md) · [Smoke Test Plan](docs/testing/smoke-test-plan.md)

## Ethics & Disclaimers

APTL uses commodity services and basic integrations. AI agents get Kali access — no enhancements to their latent capabilities beyond that. **No red-team enhancements will be added to this public repository.** An autonomous cyber-operations range is under development as a separate project.

You are responsible for following all applicable laws. The author takes no responsibility for your use of this lab. The repository contains intentional **test credentials** (covered by `.gitguardian.yaml`) for lab functionality — dummy values for educational use, not production secrets.

## License

MIT

---

*10-23 AI hacker shenanigans 🚓*
