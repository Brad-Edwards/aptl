[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=Brad-Edwards_aptl&token=4dd88be3421d6d030a4615b86ac8ab0e3c9eb4d3)](https://sonarcloud.io/summary/new_code?id=Brad-Edwards_aptl)  

# APTL (Advanced Purple Team Lab)

**Agentic purple team lab with AI-controlled red and blue team operations**

> **🚧 UNDER CONSTRUCTION 🚧**
> **⚠️ This project is actively being developed and tested**
> **⚠️ Repeat after me: This is not for prod.**
> **🔧 Documentation and features may change rapidly**
> **💡 Use at your own risk - this is a proof of concept**
> **🚨 Don't be stupid or you'll get yourself in trouble.**

## What is APTL?

A Docker-based purple team lab. One command brings up an isolated network with enterprise target infrastructure, a red team attack platform, a full SOC stack, and AI agent integration -- everything needed to run realistic attack-defend cycles.

**Target Infrastructure** -- a fictional company called TechVault Solutions, deployed as containers:

- Samba AD domain controller (`techvault.local` with user accounts, SPNs, groups)
- PostgreSQL database with seeded customer data and intentional vulnerabilities
- Vulnerable web application (SQLi, XSS, IDOR, command injection)
- Samba file server with department shares and planted credentials
- DNS server (Bind9 for internal resolution and C2 detection)
- Email server (Postfix + Dovecot for phishing simulations)
- Rocky Linux victim with SSH, Wazuh agent, Falco eBPF runtime monitoring, sudo misconfigurations

**Red Team** -- Kali Linux container with kali-tools-top10, every command logged to the SIEM. AI agents control it via MCP.

**SOC Stack** -- detection, investigation, and response:

- Wazuh SIEM (manager + indexer + dashboard) collecting logs from all containers
- Suricata IDS for network-level detection (C2, lateral movement, exfiltration)
- MISP threat intelligence platform with IOC feeds
- TheHive case management with Cortex analyzers for automated enrichment
- Shuffle SOAR for automated response playbooks

**Malware Analysis** -- reverse engineering container (Ubuntu) with radare2, yara, capa, FLOSS for binary analysis during blue team investigations.

**AI Agent Layer** -- MCP servers giving AI agents programmatic control across all of the above: red team ops, SIEM queries, threat intel, case management, SOAR playbooks, network IDS, and reverse engineering.

**Scenario Engine** -- YAML-defined attack scenarios with MITRE ATT&CK mapping. Each run captures all telemetry (Wazuh alerts, Suricata events, TheHive cases, MISP correlations, SOAR executions, container logs, MCP traces) into a self-contained archive for post-hoc analysis.

**Python CLI** (`aptl`) -- lab lifecycle, scenario execution, and run management.

**Use cases:** autonomous cyber operations research, purple team training, AI threat actor assessment.

## Demo

**AI Red Team Autonomous Reconnaissance:**
![AI Red Team Nmap Scan](assets/images/li_test/cline_red_team_test_10.png)

**Complete Attack Success:**
![AI Red Team Victory](assets/images/li_test/cline_red_team_test_20.png)

*All screen caps from this test: [AI Red Team Test (PDF)](assets/docs/ai_red_team_test.pdf)*

---

ALWAYS monitor AI red-team agents during scenarios.

## Ethics Statement

Defenders and decision-makers need examples of realistic adversarial use cases to guide planning and investments. Attackers are already aware of and experimenting with AI-enabled cyber operations. This lab uses consumer grade, commodity services and basic integrations that do not advance existing capabilities. No enhancements are made to AI agents' latent knowledge and abilities beyond granted Kali access.

No red-team enhancements will be added to this public repository.

An autonomous cyber operations range is currently under-development as a separate project.

**⚠️ WARNING: This lab enables AI agents to run actual penetration testing tools. Container escape or other security issues may occur. Monitor closely.**

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

## Quick Start

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl

pip install -e .
aptl lab start
```

Manage the lab:

```bash
aptl lab status   # Show running containers
aptl lab stop     # Stop the lab
aptl lab stop -v  # DESTROYS ALL DATA (Wazuh indexes, MISP, TheHive, configs)
```

**Access:**

- Wazuh Dashboard: <https://localhost:443> (admin/SecretPassword)
- Victim SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali SSH: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`
- Reverse Engineering SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027`

## Requirements

- Docker + Docker Compose
- Python 3.11+ (for CLI)
- 8GB+ RAM, 20GB+ disk
- Linux/macOS/WSL2
- Ports available: 443, 2022, 2023, 2027, 9200, 55000

## AI Integration (MCP)

Build all MCP servers:

```bash
./mcp/build-all-mcps.sh
```

Or build individually:

```bash
cd mcp/mcp-red && npm install && npm run build && cd ../..
cd mcp/mcp-wazuh && npm install && npm run build && cd ../..
```

Configure your AI client (Claude Code, Cursor, Cline) to connect to the server entry points at `./mcp/<server>/build/index.js`. See [MCP Integration](docs/components/mcp-integration.md) for full setup.

Test red team: Ask your AI agent "Use kali_info to show me the lab network"
Test blue team: Ask your AI agent "Use wazuh_query_alerts to show me recent alerts"

## Documentation

**Getting Started:**
- [Installation](docs/getting-started/installation.md)
- [Prerequisites](docs/getting-started/prerequisites.md)
- [Quick Start Guide](docs/getting-started/quick-start.md)

**Architecture:**
- [Overview](docs/architecture/index.md) -- Network topology, container layout, data flow
- [Networking](docs/architecture/networking.md)
- [Enterprise Infrastructure](docs/architecture/enterprise-infrastructure.md) -- TechVault design rationale

**Components:**
- [Wazuh SIEM](docs/components/wazuh-siem.md)
- [Kali Red Team](docs/components/kali-redteam.md)
- [Victim Containers](docs/components/victim-containers.md)
- [Reverse Engineering](docs/components/reverse-engineering-container.md)
- [MCP Integration](docs/components/mcp-integration.md)

**Scenarios & Runs:**
- [SOC Architecture Spec](docs/specs/soc-feature-spec.md) -- Scenario engine, run archives, collectors

**Testing:**
- [Smoke Test Plan](docs/testing/smoke-test-plan.md)

**Reference:**
- [TechVault Company Profile](docs/reference/techvault-company-profile.md)
- [TechVault OSINT Readiness](docs/reference/techvault-osint-readiness.md)
- [Container Template Guide](docs/containers/victim-template-guide.md)

**Operations:**
- [Troubleshooting](docs/troubleshooting/)
- [Known Issues](docs/known-issues/uat-findings-2026-02-23.md)

## Security Warnings

**⚠️ IMPORTANT DISCLAIMERS:**

- **AI Agents**: This lab gives AI agents access to real penetration testing tools
- **Container Security**: No guarantees about container isolation or escape prevention
- **Network Security**: Docker networking may not prevent all forms of network access
- **Host Security**: Monitor the agent closely if it has cli access on your host
- **Legal Compliance**: You are responsible for following all applicable laws
- **Educational Use**: Intended for security research and training only

**The author takes no responsibility for your use of this lab.**

## Test Credentials Notice

This repository contains **intentional test credentials** for lab functionality:

- All credentials are dummy/test values for educational use
- Covered by GitGuardian whitelist (`.gitguardian.yaml`)
- **NOT production secrets** - safe for educational environments
- Environment contains vulnerable configurations by design

## License

MIT

---

10-23 AI hacker shenanigans 🚓
