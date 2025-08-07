# Getting Started

Welcome to APTL (Advanced Purple Team Lab) - a local Docker-based purple team lab that demonstrates autonomous cyber operations while providing hands-on security training.

## What is APTL?

APTL creates a controlled environment where:

- **AI agents** can autonomously conduct cyber operations via Model Context Protocol (MCP)
- **Blue team practitioners** practice detecting and responding to automated attacks
- **Purple team exercises** simulate real-world autonomous threat scenarios
- **SIEM integration** provides enterprise-grade security monitoring and analysis

## Lab Architecture

The lab runs entirely on your local machine using Docker containers:

- **Wazuh SIEM Stack**: Complete security monitoring solution
- **Victim Containers**: Target systems with realistic services and vulnerabilities
- **Kali Red Team**: Containerized attack platform with AI integration
- **Isolated Network**: Docker network (172.20.0.0/16) containing all operations

## Quick Start

Get the lab running in minutes:

```bash
# Clone and start the lab
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

The startup script handles all prerequisites and provides connection details.

## What's Next?

1. **[Prerequisites](prerequisites.md)** - System requirements and dependencies
2. **[Installation](installation.md)** - Detailed setup process
3. **[Quick Start](quick-start.md)** - Fast deployment and basic usage

## Benefits of Local Lab

- **No Cloud Costs**: Run entirely on your local machine
- **Fast Setup**: Complete lab ready in under 10 minutes  
- **Isolated Environment**: Contained Docker networking prevents external impact
- **Consistent Experience**: Same environment every time, easy reset
- **Offline Capable**: No internet required after initial setup

## Lab Components

| Component | Purpose | Access |
|-----------|---------|--------|
| Wazuh Dashboard | SIEM interface | https://localhost:443 |
| Victim Container | Attack target | SSH: port 2022 |
| Kali Container | Red team platform | SSH: port 2023 |
| MCP Server | AI integration | Local TypeScript server |

## Security Notice

This lab contains **intentional test credentials** and vulnerable configurations for educational purposes:

- All credentials are **dummy/test values only**
- Environment is **isolated** and safe for training
- **Not for production use** - lab environment only

!!! warning "Educational Use Only"
    This lab is designed for security research, training, and educational purposes only. All activities should be contained within the lab environment.