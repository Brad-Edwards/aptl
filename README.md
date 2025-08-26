# APTL (Advanced Purple Team Lab)

**Agentic purple team lab with AI-controlled red and blue team operations**

> **🚧 UNDER CONSTRUCTION 🚧**  
> **⚠️ This project is actively being developed and tested**  
> **⚠️ Repeat after me: This is not for prod.**  
> **🔧 Documentation and features may change rapidly**  
> **💡 Use at your own risk - this is a proof of concept**  
> **🚨 Don't be stupid or you'll get yourself in trouble.**

## Agentic Purple Team Operations

AI agents autonomously execute complete attack-defend cycles:

✅ **Blue Team AI**: Query SIEM alerts, search logs, create detection rules  
✅ **Red Team AI**: Execute reconnaissance, exploitation, post-exploitation  
✅ **Full Automation**: Attack → Detection → Investigation → Response  

## Demo & Screenshots

**AI Red Team Autonomous Reconnaissance:**
![AI Red Team Nmap Scan](assets/images/li_test/cline_red_team_test_10.png)

**Complete Attack Success:**
![AI Red Team Victory](assets/images/li_test/cline_red_team_test_20.png)

*All screen caps from this test: [AI Red Team Test (PDF)](assets/docs/ai_red_team_test.pdf)*

---

🚨⚠️🚨 ALWAYS monitor AI red-team agents during scenarios 🚨⚠️🚨

## What is APTL?

**A working agentic purple team lab.** AI agents autonomously conduct attacks and defensive analysis through Model Context Protocol integration with Wazuh SIEM and Kali Linux containers.

APTL demonstrates:

- **Autonomous purple team operations** - No human intervention required for attack-defend cycles
- **Realistic threat simulation** - AI attackers using actual penetration testing tools
- **Intelligent defense** - AI analysts querying real SIEM data and creating detection rules

Use cases:

- Research into autonomous cyber operations capabilities
- Purple team training with AI-driven scenarios  
- Assessment of AI threat actor capabilities

## Ethics Statement

Defenders and decision-makers need examples of realistic adversarial use cases to guide planning and investments. Attackers are already aware of and experimenting with AI-enabled cyber operations. This lab uses consumer grade, commodity services and basic integrations that do not advance existing capabilities. No enhancements are made to AI agents' latent knowledge and abilities beyond granted Kali access.

No red-team enhancements will be added to this public repository.

An autonomous cyber operations range is currently under-development as a separate project.

**⚠️ WARNING: This lab enables AI agents to run actual penetration testing tools. Container escape or other security issues may occur. Monitor closely.**

## What's Different

- **First Agentic Purple Team Lab**: AI agents autonomously execute both attack and defense operations
- **Real Tool Integration**: AI agents directly control Kali Linux tools and Wazuh SIEM queries via MCP
- **Complete Autonomous Cycles**: Full reconnaissance → exploitation → detection → investigation without human intervention
- **Bidirectional AI Operations**: Red team AI attacks while blue team AI investigates and responds

## Components

- Wazuh SIEM (172.20.0.10-12) - Log collection and analysis
- Victim container (172.20.0.20) - Rocky Linux with Wazuh agent and Falco runtime security monitoring
- Kali container (172.20.0.30) - Attack platform with security tools, logs all red team agent's commands to the SIEM
- Blue Team MCP - Enables AI agent SIEM queries, log search, and rule creation
- Red Team MCP - Enables AI agent control of Kali tools

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

Build MCP servers for AI agent control:

```bash
# Blue Team MCP (Wazuh SIEM)
cd mcp-blue && npm install && npm run build && cd ..

# Red Team MCP (Kali Linux)
cd mcp-red && npm install && npm run build && cd ..
```

Configure your AI client to connect to:

- Blue Team: `./mcp-blue/build/index.js`
- Red Team: `./mcp-red/build/index.js`

Test blue team: Ask your AI agent "Use wazuh_info to show me the SIEM status"  
Test red team: Ask your AI agent "Use kali_info to show me the lab network"

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
