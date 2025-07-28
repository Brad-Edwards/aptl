# Advanced Purple Team Lab (APTL)

> **🚧 UNDER CONSTRUCTION 🚧**  
> **⚠️ This project is actively being developed and tested**  
> **🔧 Documentation and features may change rapidly**  
> **💡 Use at your own risk - this is a proof of concept**  
> **🚨 Don't be stupid or you'll get yourself in trouble.**

---

A shoestring budget purple team lab infrastructure using AWS and Terraform, featuring IBM qRadar Community Edition.

Lab deploys qRadar Community Edition SIEM for security event analysis.

This lab assumes you have basic understanding of AWS CLI, Terraform, and Linux admin tasks.

This is a lab environment, not for production use. qRadar trial license expires in 30 days. See IBM's [qRadar Community Edition](https://www.ibm.com/community/101/qradar/ce/) for more information.

## Features

- IBM qRadar Community Edition SIEM with comprehensive security analytics
- Kali Linux red team instance with pre-configured attack tools
- Victim machine with comprehensive log forwarding to SIEM
- Red team activity logging: structured events for commands, network activities, and authentication attempts
- Red team log routing: custom properties and log sources for qRadar analysis
- Attack simulation scripts for training exercises and correlation testing
- Terraform automation for consistent infrastructure deployment

## Overview

This project creates a purple team lab environment in AWS with:

- qRadar Community Edition 7.5 on t3a.2xlarge instance
- Victim machine on t3.micro instance
- Single VPC with both instances in same subnet
- Security groups restricting access to your IP address only

## Roadmap

### 🔜 Coming Soon (v1.1)

- ✅ **Kali MCP**: Kali Linux Model Context Protocol integration for better AI red teaming
- **Victim Machine Presets**: Windows, Linux, web apps, etc
- **Suggested Exercises**: AI-driven exercises based on what you've done
- **Challenges with Pre-Seeded SIEM Data**: Set piece challenges to practice your SIEM skills

### 🎯 Future Releases

- Additional SIEM platforms (Elastic Security, Wazuh)
- Windows victim machines
- Container-based deployments
- Automated report generation
