<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-06-01

### Added

- Complete Terraform automation for AWS deployment
- VPC with public subnet and security groups configuration
- IBM qRadar Community Edition 7.5 SIEM setup automation
- RHEL 9.6 victim machine with automated log forwarding
- System preparation and installation scripts for qRadar
- Pre-built security event generators
- MITRE ATT&CK technique simulators (T1078, T1110, T1021, T1055, T1003, T1562)
- Brute force and lateral movement attack scenarios
- Connection verification and debugging tools
- AI Red Team Agent integration with Cline/Cursor
- Documentation for AI-powered autonomous red teaming
- Complete setup and deployment guide
- Troubleshooting documentation with common issues
- Cost estimation and security considerations
- SPDX license headers (BUSL-1.1) throughout codebase
- Legal disclaimer and usage warnings
- Roadmap for upcoming features

### Known Issues

- qRadar CE limited to 5,000 EPS and 30-day trial license
- Manual ISO transfer required (~5GB file size)
- Installation process takes 1-2 hours
- High operational cost (~$280/month if left running continuously)

### Security

- Access restricted to single IP address via security groups
- Isolated VPC environment for contained testing
- Automated SSH key configuration
- Minimal attack surface on victim machine
