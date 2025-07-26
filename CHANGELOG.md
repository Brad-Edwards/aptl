<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2025-07-26

### Security

- **S3 Bucket Enumeration Protection**: Enhanced bootstrap infrastructure security to prevent cost exploitation attacks
  - Added UUID-based naming for S3 bucket: `aptl-shared-${uuid}` instead of predictable `aptl-shared-storage`
  - Added UUID-based naming for DynamoDB table: `aptl-terraform-locks-${uuid}`
  - Implemented shared S3 bucket strategy with organized folder structure for all Terraform state
- **Unified State Management**: Consolidated all Terraform state storage into single UUID-protected S3 bucket
  - Bootstrap state: `s3://aptl-shared-${uuid}/bootstrap/terraform.tfstate`
  - Main infrastructure state: `s3://aptl-shared-${uuid}/environments/dev/terraform.tfstate`
  - Future file storage: `s3://aptl-shared-${uuid}/files/` (qRadar ISOs, etc.)

### Added

- **Bootstrap State Migration**: Automated migration from local to S3 state storage
  - `migrate_bootstrap_state.sh` script for seamless state migration
  - `setup_backend.sh` script for automated main infrastructure configuration
  - Hard dependency enforcement: bootstrap must be applied before main infrastructure

### Changed

- **Required Workflow Update**: New deployment process with state migration
  1. Deploy bootstrap with local state (`terraform apply`)
  2. Migrate bootstrap state to S3 (`./migrate_bootstrap_state.sh`)
  3. Configure main infrastructure (`./setup_backend.sh`)
  4. Deploy main infrastructure (`terraform apply`)
- **Backend Configuration**: Updated main infrastructure to use dynamic bucket names from bootstrap outputs
- **Random Provider**: Added HashiCorp random provider to bootstrap for UUID generation

### Technical Notes

- All existing infrastructure remains compatible with new UUID-based naming
- Migration scripts handle AWS profile configuration automatically
- S3 bucket versioning and encryption preserved for all state files
- No breaking changes to existing variable names or module interfaces

## [1.1.1] - 2025-07-24

### Changed

- **qRadar-Only Deployment**: Simplified SIEM selection to use qRadar Community Edition as the default and primary option
  - Changed `siem_type` default from "splunk" to "qradar" in terraform.tfvars.example and variables.tf
  - Updated documentation to present qRadar as the single SIEM option
  - Preserved all Splunk infrastructure code for potential future re-enablement
- **Documentation Updates**: Removed multi-SIEM references and Splunk-specific sections from README.md and CLAUDE.md
  - Streamlined installation instructions to focus on qRadar workflow
  - Updated cost estimates to reflect qRadar-only deployment (~$287/month)
  - Removed Splunk integration from roadmap (feature already implemented but de-emphasized)

### Technical Notes

- All Splunk modules, variables, and conditional logic preserved in codebase
- No breaking changes to existing terraform configuration
- Users can still manually set `siem_type = "splunk"` if needed
- Validation continues to accept both "splunk" and "qradar" values

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
