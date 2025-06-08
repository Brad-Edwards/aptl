<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-06-07

### Added

- **Splunk Enterprise Security support**: Alternative to qRadar using c5.4xlarge instance
  - SIEM selection via `siem_type` variable in terraform.tfvars
  - Automated Splunk installation and configuration scripts
  - Pre-configured `keplerops-aptl-redteam` index for red team log separation
- **Kali red team activity logging**: Structured logging of attack commands and network activities
  - `log_redteam_command()`, `log_redteam_network()`, `log_redteam_auth()` functions
  - SIEM-specific rsyslog routing (port 5514 for Splunk, 514 for qRadar)
  - Attack simulation scripts: `simulate_redteam_operations.sh`, `simulate_port_scan.sh`
  - Structured log fields: RedTeamActivity, RedTeamCommand, RedTeamTarget, RedTeamResult

### Changed

- Updated Splunk version references to use current 9.4.x series downloads
- Enhanced Kali Linux instance configuration with red team logging integration
- Improved SIEM configuration scripts for both platforms

### Fixed

- Outdated Splunk download URLs causing 404 errors during installation
- MCP server terraform path resolution issues after infrastructure reorganization
- Template syntax errors in Kali user_data script

## [1.0.1] - 2025-06-03

### Added

- **Kali Linux Red Team Instance**: New t3.micro Kali Linux instance for red team operations
- **Model Context Protocol (MCP) Server**: AI-powered red team tool integration
  - `kali_info` tool for lab instance information
  - `run_command` tool for remote command execution on lab targets
  - TypeScript implementation with full test suite
  - Integration with VS Code/Cursor and Cline AI assistants
- **Enhanced Security Groups**: Precise traffic rules for realistic attack scenarios
  - Kali can attack victim on all ports
  - Kali and victim can send logs to SIEM
  - Removed overly broad subnet-wide access
- **Documentation Updates**:
  - Architecture diagram with attack flow visualization
  - MCP setup instructions for both Cursor and Cline
  - Project-local configuration examples

### Fixed

- Terraform path resolution issues in MCP server
- JSON configuration syntax errors in project settings
- Inter-instance connectivity for red team exercises

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
