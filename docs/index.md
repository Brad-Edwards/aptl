# APTL — Advanced Purple Team Lab

Docker-based purple team lab: Wazuh SIEM + enterprise infrastructure + Kali + AI agent integration via MCP.

## Quick Start

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

**Access:**

- Wazuh Dashboard: <https://localhost:443> (admin/SecretPassword)
- Victim SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali SSH: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## Requirements

- Docker + Docker Compose
- Python 3.11+
- 8GB RAM, 20GB disk
- Ports: 443, 2022, 2023, 9200, 55000

## Documentation

### Getting Started
- [Installation](getting-started/installation.md)
- [Prerequisites](getting-started/prerequisites.md)
- [Quick Start Guide](getting-started/quick-start.md)

### Architecture
- [Overview](architecture/index.md)
- [Networking](architecture/networking.md)
- [Enterprise Infrastructure](architecture/enterprise-infrastructure.md) — TechVault design rationale

### Components
- [Wazuh SIEM](components/wazuh-siem.md)
- [Kali Red Team](components/kali-redteam.md)
- [Victim Containers](components/victim-containers.md)
- [MCP Integration](components/mcp-integration.md)
- [Reverse Engineering](components/reverse-engineering-container.md)

### Architecture Decision Records
- [ADR Index](adrs/README.md) -- Why we built it this way

### Scenario Description Language (SDL)
- [SDL Overview](sdl/index.md) — What the SDL is and how to use it
- [Sections Reference](sdl/sections.md) — Complete reference for all 21 sections
- [Parser Behavior](sdl/parser.md) — Key normalization, shorthands, SDL-only parsing
- [Semantic Validation](sdl/validation.md) — Cross-reference checks (22 passes)
- [Design Precedents](sdl/precedents.md) — Where each element comes from
- [Limitations](sdl/limitations.md) — What the SDL cannot express yet
- [Testing](sdl/testing.md) — Unit tests, stress tests, fuzz tests

### Scenarios & Runs
- [SOC Architecture Spec](specs/soc-feature-spec.md) — Historical pre-SDL runtime spec retained for context

### Testing
- [Smoke Test Plan](testing/smoke-test-plan.md) — Historical full-stack plan for the pre-SDL scenario engine

### Reference
- [TechVault Company Profile](reference/techvault-company-profile.md)
- [TechVault OSINT Readiness](reference/techvault-osint-readiness.md)
- [Container Template Guide](containers/victim-template-guide.md)

### Operations
- [Deployment](deployment.md)
- [Troubleshooting](troubleshooting/)
- [Known Issues — UAT Findings](known-issues/uat-findings-2026-02-23.md)

### History
- [Smoke Test Results 2026-02-08](history/smoke-test-results-2026-02-08.md)
- [MCP Smoke Test Results 2026-02-22](components/mcp-smoke-test-results-2026-02-22.md)
