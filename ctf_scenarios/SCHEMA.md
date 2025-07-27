# CTF Scenarios JSON Schema Reference

This document defines the structure and meaning of values in `scenarios.json`.

## Schema Overview

```json
{
  "ctf_scenarios": {
    "description": "string",
    "version": "semver",
    "last_updated": "YYYY-MM-DD",
    "scenarios": {
      "<difficulty_category>": {
        "description": "string",
        "estimated_time": "string",
        "scenarios": {
          "<scenario_id>": {
            "name": "string",
            "description": "string", 
            "attack_vectors": ["array of strings"],
            "skills_tested": ["array of strings"],
            "difficulty": "N/10",
            "flags": "integer",
            "services": ["array of strings"],
            "path": "relative/path/"
          }
        }
      }
    },
    "usage": { "object" },
    "blue_team_training": { "object" },
    "red_team_mcp_integration": { "object" }
  }
}
```

## Field Definitions

### Root Level

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | High-level description of the scenario collection |
| `version` | string | Semantic version (major.minor.patch) |
| `last_updated` | string | ISO date (YYYY-MM-DD) of last modification |

### Difficulty Categories

| Category | Level Range | Description |
|----------|-------------|-------------|
| `basic` | 1-3/10 | Entry-level scenarios for fundamental skills |
| `intermediate` | 4-7/10 | Mid-level scenarios requiring technical analysis |
| `hard` | 8-10/10 | Advanced scenarios with complex exploitation chains |

### Scenario Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✓ | Human-readable scenario name |
| `description` | string | ✓ | One-line summary of the scenario |
| `attack_vectors` | array[string] | ✓ | Primary attack techniques used |
| `skills_tested` | array[string] | ✓ | Skills and knowledge areas assessed |
| `difficulty` | string | ✓ | Numeric rating from 1/10 to 10/10 |
| `flags` | integer | ✓ | Number of flags to capture |
| `services` | array[string] | ✓ | Required system services/software |
| `path` | string | ✓ | Relative path to scenario directory |

## Difficulty Rating Scale

### 1-2/10: Beginner
- **Target Audience**: New to penetration testing
- **Prerequisites**: Basic command line knowledge
- **Complexity**: Single attack vector, obvious vulnerabilities
- **Time**: 5-15 minutes
- **Example**: Directory traversal, default credentials

### 3-4/10: Novice
- **Target Audience**: Some security experience
- **Prerequisites**: Familiarity with common tools (nmap, etc.)
- **Complexity**: Simple multi-step attacks
- **Time**: 10-20 minutes
- **Example**: Simple SQL injection, basic privilege escalation

### 5-6/10: Intermediate
- **Target Audience**: Junior security professionals
- **Prerequisites**: Understanding of web apps, networking, Linux
- **Complexity**: Technical analysis required, multiple attack paths
- **Time**: 20-40 minutes
- **Example**: Complex SQL injection, sudo misconfigurations

### 7-8/10: Advanced
- **Target Audience**: Experienced penetration testers
- **Prerequisites**: Binary analysis, exploit development basics
- **Complexity**: Custom exploitation, manual analysis
- **Time**: 45-75 minutes
- **Example**: Buffer overflows, reverse engineering

### 9-10/10: Expert
- **Target Audience**: Senior security experts
- **Prerequisites**: Advanced exploitation, attack chaining
- **Complexity**: Multi-stage attacks, advanced persistence
- **Time**: 60-120+ minutes
- **Example**: APT simulation, zero-day development

## Attack Vector Categories

### Web Application
- `directory_traversal` - Path manipulation attacks
- `sql_injection` - Database injection vulnerabilities
- `union_based_injection` - SQL UNION query exploitation
- `web_enumeration` - Directory and file discovery
- `robots.txt_disclosure` - Information disclosure via robots.txt

### Network Services
- `ssh_brute_force` - SSH password attacks
- `ftp_anonymous_login` - FTP anonymous access exploitation
- `telnet_authentication` - Telnet credential attacks
- `service_enumeration` - Network service discovery
- `credential_attacks` - Authentication bypass techniques
- `clear_text_protocols` - Unencrypted protocol exploitation

### System Exploitation
- `sudo_misconfiguration` - Privilege escalation via sudo
- `suid_exploitation` - SUID binary abuse
- `cron_manipulation` - Scheduled task exploitation
- `buffer_overflow` - Memory corruption attacks
- `stack_manipulation` - Stack-based exploitation

### Advanced Techniques
- `lateral_movement` - Post-compromise network traversal
- `file_share_access` - Network file system exploitation
- `persistence` - Maintaining system access
- `attack_chaining` - Multi-vector attack sequences
- `shellcode_execution` - Custom payload execution

## Skills Tested Categories

### Reconnaissance
- `basic_web_scanning` - Web application enumeration
- `service_enumeration` - Network service identification
- `system_enumeration` - Host-based information gathering
- `ftp_protocol_basics` - FTP service interaction and navigation
- `file_system_navigation` - Remote file system exploration

### Exploitation
- `password_attacks` - Credential-based attacks
- `sql_injection_techniques` - Database exploitation methods
- `binary_exploitation` - Memory corruption exploitation
- `linux_privilege_escalation` - Unix/Linux privilege escalation
- `legacy_protocol_exploitation` - Attack techniques for older protocols
- `credential_discovery` - Finding and extracting authentication data
- `data_discovery` - Locating sensitive files and information

### Analysis
- `web_app_analysis` - Web application security assessment
- `binary_analysis` - Executable file analysis
- `database_interaction` - Database manipulation techniques
- `memory_corruption` - Memory-based vulnerability exploitation
- `command_execution` - Remote command execution techniques
- `data_exfiltration` - Data extraction and transfer methods

### Advanced
- `exploit_development` - Custom exploit creation
- `attack_chaining` - Multi-stage attack coordination
- `network_pivoting` - Network traversal techniques
- `persistence_techniques` - Maintaining access methods
- `gdb_debugging` - GNU debugger usage for exploitation

## Service Dependencies

### Web Stack
- `apache2` - Web server
- `mysql-server` - Database server
- `php` - Server-side scripting
- `nginx` - Alternative web server

### System Services
- `openssh-server` - SSH daemon
- `samba` - SMB/CIFS file sharing
- `nfs-kernel-server` - Network File System
- `vsftpd` - Very Secure FTP Daemon
- `telnetd` - Telnet daemon
- `xinetd` - Extended Internet daemon

### Development Tools
- `gcc` - GNU Compiler Collection
- `gdb` - GNU Debugger
- `python3` - Python interpreter

### Custom Components
- `custom_binaries` - Specially compiled vulnerable programs
- `system_users` - User accounts with specific configurations
- `network_service_port_XXXX` - Custom network services

## Time Estimates

Time estimates represent **total scenario completion time** including:
- Initial reconnaissance and enumeration
- Vulnerability identification and analysis
- Exploitation and flag capture
- Basic documentation of findings

**Note**: Times may vary significantly based on:
- Individual skill level and experience
- Tool familiarity and automation usage
- Depth of analysis performed
- Documentation requirements

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-27 | Initial schema definition |

## Extending the Schema

When adding new scenarios:

1. **Follow naming conventions**: Use lowercase with underscores
2. **Maintain difficulty progression**: Ensure ratings align with complexity
3. **Document new attack vectors**: Add to this schema if introducing new techniques
4. **Update version**: Increment appropriately (patch for fixes, minor for new scenarios)
5. **Test thoroughly**: Validate time estimates and difficulty ratings

## Validation

The schema should be validated to ensure:
- All required fields are present
- Difficulty ratings are within 1-10 range
- Time estimates follow format guidelines
- Path references point to existing directories
- Service dependencies are accurate