# APTL (Advanced Purple Team Lab)

> **🚧 UNDER CONSTRUCTION 🚧**  
> **⚠️ This project is actively being developed and tested**  
> **🔧 Documentation and features may change rapidly**  
> **💡 Use at your own risk - this is a proof of concept**  
> **🚨 Don't be stupid or you'll get yourself in trouble.**

## AI Agent Integration

✅ **Red Team MCP**: AI agents control Kali Linux for autonomous attacks  
✅ **Blue Team MCP**: AI agents query Wazuh SIEM for detection and analysis  
✅ **Complete Workflow**: Red team attacks → SIEM detection → Blue team investigation  

## Demo & Screenshots

**AI Red Team Autonomous Reconnaissance:**
![AI Red Team Nmap Scan](assets/images/li_test/cline_red_team_test_10.png)

**Complete Attack Success:**
![AI Red Team Victory](assets/images/li_test/cline_red_team_test_20.png)

*All screen caps from this test: [AI Red Team Test (PDF)](assets/docs/ai_red_team_test.pdf)*

---

🚨⚠️🚨 ALWAYS monitor AI red-team agents during scenarios 🚨⚠️🚨

## What is APTL?

Docker lab with Wazuh SIEM + victim containers + Kali red team platform. AI agents control both red team attacks (Kali MCP) and blue team analysis (Wazuh MCP) for complete purple team exercises.

APTL is meant to support three use cases:

- Inexpensive purple team training
- Assessment of the capabilities autonomous cyber operations available to relatively unsophisticated attackers
- Research

## Ethics Statement

Defenders and decision-makers need examples of realistic adversarial use cases to guide planning and investments. Attackers are already aware of and experimenting with AI-enabled cyber operations. This lab uses consumer grade, commodity services and basic integrations that do not advance existing capabilities. No enhancements are made to AI agents' latent knowledge and abilities beyond granted Kali access.

No red-team enhancements will be added to this public repository.

An autonomous cyber operations range is currently under-development as a separate project.

**⚠️ WARNING: This lab enables AI agents to run actual penetration testing tools. Container escape or other security issues may occur. Monitor closely.**

## What's Different

- **Autonomous AI Control**: AI agents directly execute real penetration testing tools via Model Context Protocol
- **Complete Attack Cycles Demonstrated**: Full autonomous reconnaissance → exploitation → post-exploitation without human intervention
- **Realistic Environment**: Containerized lab with actual SIEM logging
- **Purple Team Focus**: Purpose-built for training defenders against AI attackers

## Components

- Wazuh SIEM (172.20.0.10-12) - Log collection and analysis
- Victim container (172.20.0.20) - Rocky Linux with Wazuh agent integration
- Kali container (172.20.0.30) - Attack platform with security tools
- MCP server - Enables AI agent control of Kali tools

## Quick Start

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

**Access:**

- Wazuh Dashboard: <https://localhost:443> (admin/SecretPassword)  
- Victim SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali SSH: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## Requirements

- Docker + Docker Compose
- 8GB+ RAM, 20GB+ disk
- Linux/macOS/WSL2
- Ports available: 443, 2022, 2023, 9200, 55000

## AI Integration (MCP)

Build MCP server for AI agent control:

```bash
cd mcp && npm install && npm run build && cd ..
```

Configure your AI client to connect to `./mcp/dist/index.js`

Test: Ask your AI agent "Use kali_info to show me the lab network"

## Documentation

- [Getting Started](docs/getting-started/) - Setup and prerequisites
- [Architecture](docs/architecture/) - Network design and components  
- [Components](docs/components/) - Individual service details
- [Troubleshooting](docs/troubleshooting/) - Common issues and fixes

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
