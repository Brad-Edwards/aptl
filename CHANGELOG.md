
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.3] - 2025-08-23

### Added

- **mcp-red auto-targets Kali box** - this is a security and agent ergonomics feature.

### Fixed

## [2.0.2] - 2025-08-23

### Added

- **Wazuh Agent Installation**: Added Wazuh agent (monitor only)installation to victim container

### Fixed

- **Wazuh SIEM Configuration**: Fixed SIEM configuration to use correct port and IP address
  - Changed port from 514 to 1514
  - Changed IP address from 172.20.0.10 to 172.20.0.11

### Removed

- **Victim syslog streaming to SIEM**: Removed syslog streaming to SIEM

## [2.0.1] - 2025-08-15

### Added

- **Wazuh Blue Team MCP Server**: AI agent integration for SIEM operations
  - Query alerts and logs via OpenSearch API
  - Create custom detection rules
  - Get SIEM status and configuration

### Fixed

- Documentation cleanup and consistency improvements

## [2.0.0] - 2025-08-06

### Changed

- **Complete Architecture Overhaul**: Migrated from AWS/Terraform to local Docker deployment
  - Replaced AWS EC2 instances with Docker containers
  - Replaced qRadar Community Edition with Wazuh SIEM stack

- **SIEM Change**: Default SIEM changed to Wazuh for low-resource open-source local deployment

- **Documentation Updates**: Updated to reflect new Docker infrastructure
  - All commands updated for Docker environment
  - MkDocs documentation structure

- **Container Architecture**: Five-container Docker Compose deployment

### Removed

- All AWS/Terraform infrastructure code
- qRadar Community Edition integration

### Breaking Changes

- Complete deployment model change from AWS to Docker
- Different network addressing scheme
- New access methods (SSH port forwarding vs AWS)
- SIEM interface change (Wazuh vs qRadar)

## [1.1.6] - 2025-07-30

### Added

- **Possible Game CTF Scenarios**: Added notes for possible game CTF scenarios
  - MC bleedingpipe - picking on MC is a crime
  - phpBB cred stuffing - picking on php is not
  - capcom.sys driver - oldie but a goodie

### Fixed

- **Kali Dockerfile**: Properly bootstrap GPG keyring without insecure flags
  - Removed dangerous `--allow-insecure-repositories` and `--allow-unauthenticated` flags
  - Simplified keyring setup by using pre-installed keyring in base image
  - Ensured proper keyring update before package installation

## [1.1.5] - 2025-07-28

### Security

- **Network Isolation**: Enhanced security for AI red team operations to prevent unintended external access
  - Removed internet gateway access from Kali and victim instances to contain automated activities
  - Implemented internal-only communication between lab instances using security group references
  - Preserved SIEM internet access for updates and licensing requirements
  - Maintained admin SSH access through bastion host for troubleshooting and management

### Fixed

- **Network Module Dependencies**: Resolved circular dependency issues in security group configurations
  - Separated security group rules into explicit resources to break circular references
  - Improved terraform planning and apply reliability for network infrastructure
  - Enhanced network module maintainability and extensibility

### Technical Notes

- Network isolation specifically designed for autonomous AI red team scenarios
- Lab instances can communicate internally but cannot initiate external connections
- SIEM maintains external connectivity for proper security monitoring functionality
- All existing functionality preserved with enhanced security boundaries
- Added explicit protocol support (TCP, UDP, ICMP, ESP, AH, GRE) and comprehensive admin access for all scenario types

## [1.1.4] - 2025-07-27

### Added

- **VitePress Documentation Site**: Complete documentation infrastructure with modern static site generation
  - Professional documentation site with navigation, search, and responsive design
  - Mermaid diagram support for architecture visualization
  - Optimized for GitHub Pages deployment with proper base path configuration
- **Comprehensive Documentation Restructure**: Broke down monolithic README into focused, topic-specific guides
  - `getting-started.md` - Prerequisites, setup process, cost estimation, and security considerations
  - `deployment.md` - Infrastructure deployment steps, timing, access details, and cleanup procedures
  - `qradar-setup.md` - qRadar installation, configuration, and red team logging setup
  - `red-team-mcp.md` - Kali MCP server setup, AI client configuration, and available tools
  - `exercises.md` - Purple team exercises, MITRE ATT&CK techniques, and simulation scripts
  - `ai-red-teaming.md` - Autonomous attack demonstrations and AI agent configuration
  - `architecture.md` - Detailed system design, network topology, and component descriptions
  - `troubleshooting.md` - Common issues, debugging procedures, and resolution steps

### Changed

- **README Focus**: Restructured main README to emphasize autonomous cyber operations purpose
  - Clear articulation of blue team practice and autonomous cyber weapons awareness objectives
  - Emphasis on educational demonstration of AI-driven attack capabilities
  - Direct links to comprehensive documentation site for technical details
  - Streamlined content removing duplication with detailed documentation pages
- **Technical Tone**: Adjusted documentation tone to be more professional and technical
  - Removed marketing-style language in favor of neutral, technical descriptions
  - Maintained focus on educational and awareness objectives
  - Improved clarity and precision in technical explanations

### Technical Notes

- All content functionally equivalent to original README with improved organization
- GitHub Pages integration with proper link structure to VitePress site
- Documentation site available at `https://brad-edwards.github.io/aptl/`
- Preserved all commands, scripts, and technical procedures without modification

## [1.1.3] - 2025-07-26

### Added

- **Cursor IDE Integration**: Development environment configuration for enhanced AI assistant support
  - `.cursor/environment.json` for automated dependency installation and MCP server building
  - `.cursor/mcp.json` for red team MCP server integration with proper absolute paths
  - `.cursor/rules/no-jumping-ahead.mdc` for AI assistant behavior guidelines and technical writing standards

### Changed

- **Git Ignore Updates**: Modified `.gitignore` to selectively include Cursor configuration files
  - Added specific inclusions for `.cursor/environment.json`, `.cursor/mcp.json`, and `.cursor/rules/`
  - Maintained exclusion of other `.cursor/` files for privacy

## [1.1.2] - 2025-07-26

### Security

- **S3 Bucket Enumeration Protection**: Enhanced infrastructure security to prevent cost exploitation attacks
  - Implemented UUID-based naming for all S3 buckets to prevent predictable bucket enumeration
  - Bootstrap bucket: `aptl-bootstrap-${uuid}` instead of predictable names
  - Main infrastructure bucket: `aptl-main-${uuid}` for state storage
  - DynamoDB tables also use UUID suffixes for consistency
- **Separate State Storage**: Implemented isolated S3 buckets for different infrastructure components
  - Bootstrap infrastructure manages its own state bucket
  - Main infrastructure manages its own separate state bucket
  - No hardcoded bucket names in repository code

### Added

- **State Migration Automation**: Helper scripts for seamless S3 state migration
  - `create_backend.sh` scripts in both bootstrap and main infrastructure directories
  - Automated backend.tf generation from terraform outputs
  - Simplified workflow: deploy → create backend → migrate state

### Changed

- **Required Deployment Workflow**: Updated to use separate S3 buckets with UUID naming
  1. Deploy bootstrap: `terraform apply` → `./create_backend.sh` → `terraform init -migrate-state`
  2. Deploy main infrastructure: `terraform apply` → `./create_backend.sh` → `terraform init -migrate-state`
- **Random Provider**: Added HashiCorp random provider to both bootstrap and main infrastructure
- **Backend Configuration**: Each component creates and manages its own S3 backend

### Technical Notes

- All bucket names use UUIDs generated at deployment time
- No breaking changes to existing variable names or module interfaces
- State storage is fully isolated between bootstrap and main infrastructure
- Migration scripts handle the complexity of moving from local to S3 state

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
