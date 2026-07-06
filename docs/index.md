# APTL—Advanced Purple Team Lab

Docker-based purple team lab: Wazuh SIEM + enterprise infrastructure + Kali + AI agent integration via MCP.

## Quick Start

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pipx install aptl-labs
aptl lab start
```

Clone the repo even with the published package: `aptl lab start` reads the
Compose topology, scenarios, and config templates from the checkout.
[pipx](https://pipx.pypa.io/) isolates the CLI in its own virtualenv, so the
[PEP 668](https://peps.python.org/pep-0668/) system-`pip` block on modern
Debian/Ubuntu/WSL2 hosts never applies (`sudo apt install pipx` to get it). To
run from source instead, use a virtualenv editable install
(`python3 -m venv .venv && source .venv/bin/activate && pip install -e .`; needs
`python3-venv`). See [Prerequisites](getting-started/prerequisites.md).

**Access:**

- Wazuh Dashboard: <https://localhost:443> (admin/SecretPassword)
- Victim SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali SSH: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## Requirements

- Docker + Docker Compose
- Python 3.11+
- RAM: 8GB for the curated scenarios; more than 20GB for the full `techvault-operational` stack
- 20GB+ disk
- Ports: 443, 2022, 2023, 9200, 55000

## Documentation

### Getting Started
- [Installation](getting-started/installation.md)
- [Prerequisites](getting-started/prerequisites.md)
- [Quick Start Guide](getting-started/quick-start.md)

### Architecture
- [Overview](architecture/index.md)
- [Networking](architecture/networking.md)
- [Enterprise Infrastructure](architecture/enterprise-infrastructure.md): TechVault design rationale

### Components
- [Wazuh SIEM](components/wazuh-siem.md)
- [Wazuh Active Response](components/wazuh-active-response.md)
- [Default Defensive Posture](components/default-defensive-posture.md): what ships enabled vs disabled at first boot
- [Kali Red Team](components/kali-redteam.md)
- [Red Team Activity Taxonomy](red-team-taxonomy.md): OCSF activity classes the Kali MCP server emits
- [Victim Containers](components/victim-containers.md)
- [MCP Integration](components/mcp-integration.md)
- [Reverse Engineering](components/reverse-engineering-container.md)

### Architecture Decision Records
- [ADR Index](adrs/README.md) -- Why we built it this way

### Scenario Authoring
- [Authoring Boundary](sdl/index.md): Current ACES-owned scenario handoff
- [Curated ACES Variants](sdl/techvault-curated-variants.md): Supported startup catalog variants
- [TechVault Static Validation Gate](aces/techvault-static-validation-gate.md): Current static scenario gate
- [TechVault Live Validation Gate](aces/techvault-live-validation-gate.md): Current runtime realization gate

### Scenarios & Runs
- [SOC Architecture Spec](specs/soc-feature-spec.md): Historical pre-SDL runtime spec retained for context
- [Web GUI Design Specification](specs/web-gui-design.md): v1 product scope, route map, interaction design, component inventory, and implementation hand-off

### Testing
- [Smoke Test Plan](testing/smoke-test-plan.md): Historical full-stack plan for the pre-SDL scenario engine

### Reference
- [TechVault Scenario Overview](reference/techvault-scenario-overview.md): What the default range contains—topology, targets, SOC stack, planted vulnerabilities, and curated variants
- [TechVault Company Profile](reference/techvault-company-profile.md)
- [TechVault OSINT Readiness](reference/techvault-osint-readiness.md)
- [Container Template Guide](containers/victim-template-guide.md)

### Operations
- [Deployment](deployment.md)
- [Troubleshooting](troubleshooting/)
