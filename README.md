# APTL (Advanced Purple Team Lab)

> **🚧 UNDER CONSTRUCTION 🚧**  
> **⚠️ This project is actively being developed and tested**  
> **🔧 Documentation and features may change rapidly**  
> **💡 Use at your own risk - this is a proof of concept**  
> **🚨 Don't be stupid or you'll get yourself in trouble.**

---

## What is APTL?

Docker lab with Wazuh SIEM + victim containers + Kali red team platform. AI agents can control Kali via MCP for autonomous attacks.

**⚠️ WARNING: This lab enables AI agents to run actual penetration testing tools. Container escape or other security issues may occur. Use only in isolated environments.**

## Components

- Wazuh SIEM (172.20.0.10-12) - Log collection and analysis
- Victim container (172.20.0.20) - Rocky Linux with SSH/HTTP/FTP
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
- **Host Security**: Use only on dedicated/disposable systems
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

BUSL-1.1

---

## Note

10-23 AI hacker shenanigans 🚓