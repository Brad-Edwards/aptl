<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Advanced Purple Team Lab (APTL)

> **🚧 UNDER CONSTRUCTION 🚧**  
> **⚠️ This project is actively being developed and tested**  
> **🔧 Documentation and features may change rapidly**  
> **💡 Use at your own risk - this is a proof of concept**  
> **🚨 Don't be stupid or you'll get yourself in trouble.**

---

## Demonstration of Autonomous Cyber Operations

**What happens when AI agents can conduct cyber operations autonomously?**

APTL demonstrates autonomous cyber operations through a controlled lab environment where AI agents can execute attack scenarios while human defenders practice monitoring and response using enterprise SIEM technology.

## Purpose and Scope

This lab serves two critical purposes:

### Blue Team Practice

- **Defensive Training**: Human blue team practitioners practice detecting and responding to autonomous attacks
- **SIEM Correlation**: Development of detection rules for automated attack patterns
- **Response Procedures**: Training for incident response against autonomous threat actors
- **Pattern Recognition**: Learning to distinguish automated vs. human attack behaviors

### Autonomous Cyber Weapons Awareness

- **Emerging Threat Landscape**: Demonstration of how AI agents can autonomously conduct cyber operations
- **Capability Assessment**: Understanding the current state of autonomous attack capabilities
- **Defense Implications**: Exploring what autonomous threats mean for defensive strategies
- **Policy Considerations**: Raising awareness of autonomous cyber weapons implications

## What This Lab Demonstrates

### Autonomous Attack Capabilities

- AI agents with access to penetration testing tools via Model Context Protocol (MCP)
- Autonomous vulnerability discovery, exploitation, and persistence establishment
- Real-time attack adaptation based on system responses
- Structured logging of autonomous activities for analysis

### Educational Environment

- Controlled infrastructure preventing real-world impact
- Pre-configured scenarios for consistent training
- Enterprise SIEM integration for realistic defensive practice
- Purple team exercises simulating autonomous threat scenarios

**This lab provides both practical blue team training and awareness of the evolving autonomous cyber threat landscape.**

## Technical Architecture

- IBM qRadar Community Edition SIEM for enterprise-grade log analysis
- Kali Linux red team instance with MCP-enabled AI agent access
- Victim machine with comprehensive log forwarding
- Terraform-automated AWS infrastructure deployment

## Documentation

- **[Getting Started](https://brad-edwards.github.io/aptl/getting-started.html)** - Prerequisites, setup, and cost considerations
- **[Deployment](https://brad-edwards.github.io/aptl/deployment.html)** - Infrastructure deployment and access
- **[qRadar Setup](https://brad-edwards.github.io/aptl/qradar-setup.html)** - SIEM installation and configuration
- **[Red Team MCP](https://brad-edwards.github.io/aptl/red-team-mcp.html)** - AI agent integration and tools
- **[Purple Team Exercises](https://brad-edwards.github.io/aptl/exercises.html)** - Training scenarios and MITRE techniques
- **[AI Red Teaming](https://brad-edwards.github.io/aptl/ai-red-teaming.html)** - Autonomous attack demonstrations
- **[Architecture](https://brad-edwards.github.io/aptl/architecture.html)** - Detailed system design
- **[Troubleshooting](https://brad-edwards.github.io/aptl/troubleshooting.html)** - Common issues and solutions

## DISCLAIMER

- The author takes no responsibility for your use of this lab.
- You are solely responsible for whether you are in compliance with the laws of your jurisdiction
- You are solely responsible for following the terms and conditions of any services or applications you use.

### Test Credentials Notice

This repository contains **intentional test credentials** for security training and CTF scenarios. These credentials are:

- **Hardcoded by design** for lab functionality
- **Not production secrets** - they are dummy/test values only
- **Safe for educational use** in isolated lab environments
- **Covered by GitGuardian whitelist** (see `.gitguardian.yaml`)

**⚠️ These are NOT real production credentials and pose no security risk.**

## Quick Start

See the [Getting Started Guide](https://brad-edwards.github.io/aptl/getting-started.html) for complete setup instructions.

## Contributing

This is an early stage demo project. Feel free to fork and adapt for your personal needs.

## License

BUSL-1.1

---

*10-23 AI hacker shenanigans 🚓*
