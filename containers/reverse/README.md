# APTL Reverse Engineering Container

This directory contains the reverse engineering container for the Purple Team Lab reverse engineering demo scenarios.

## Architecture

The reverse engineering container provides a comprehensive malware analysis and binary reverse engineering environment with tools for:

- Binary analysis and disassembly  
- String extraction and pattern matching
- Capability analysis and signature generation
- Memory dump analysis
- Code signing verification

## Base Configuration

Built on Ubuntu 22.04 LTS with:

- SSH access (labadmin user)  
- Wazuh SIEM agent integration
- Falco runtime security monitoring
- Systemd service management
- Rsyslog forwarding to Wazuh Manager

## Reverse Engineering Tools

### Core Analysis Tools

- **Radare2 (r2)**: Binary analysis framework with disassembler, debugger, and hex editor
- **Binutils**: GNU binary utilities (strings, objdump, nm, readelf)
- **LLVM**: Modern compiler infrastructure and binary tools
- **YARA**: Pattern matching engine for malware identification
- **UPX**: Ultimate Packer for eXecutables - packer/unpacker
- **osslsigncode**: Code signing verification and manipulation

### Advanced Analysis

- **FLOSS**: FireEye Labs Obfuscated String Solver for advanced string extraction
- **CAPA**: Capability analysis tool for malware functionality mapping
- **Java Runtime**: OpenJDK 17 for Ghidra headless analysis (future integration)

### Workspace Structure

```
/home/labadmin/reverse-workspace/
├── samples/     # Binary samples for analysis
├── analysis/    # Analysis output and reports  
├── output/      # Generated signatures and IOCs
├── scripts/     # Custom analysis scripts
└── rules/       # YARA rules and detection patterns
```

## Usage

### Local Development

```bash
docker build -t aptl-reverse:latest .
```

### Container Access

```bash
# Access reverse engineering container
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2026
```

### Quick Analysis

```bash
# Run basic analysis on a binary
analyze /path/to/binary

# Navigate to workspace
re_workspace

# Run YARA scan
yara_scan rules/basic_indicators.yar samples/malware.exe
```

## Network Configuration

- **Container IP**: 172.20.0.26
- **SSH Port**: 2026  
- **SIEM Integration**: Logs forwarded to wazuh.manager (172.20.0.10)

## Services

All containers include the standardized service stack:

### Core Services

- **SSH Server**: Remote access and MCP integration
- **Wazuh Agent**: SIEM telemetry and alerts
- **Falco**: Runtime security monitoring  
- **Rsyslog**: Log forwarding to SIEM

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SIEM_IP` | Wazuh Manager IP | `172.20.0.10` |
| `LABADMIN_SSH_KEY_FILE` | SSH public key path | `/keys/aptl_lab_key.pub` |

## Analysis Workflow

1. **Upload samples** to `/home/labadmin/reverse-workspace/samples/`
2. **Run basic analysis**: `analyze <binary_file>`
3. **Review results** in `/home/labadmin/reverse-workspace/analysis/`
4. **Generate signatures** using YARA rules in `rules/` directory
5. **Export findings** to `output/` directory

## Troubleshooting

### SSH Access

```bash
docker exec aptl-reverse cat /home/labadmin/.ssh/authorized_keys
```

### SSH Service

```bash
docker exec aptl-reverse journalctl -u sshd -f
```

### Log Forwarding

```bash
docker exec aptl-reverse cat /etc/rsyslog.d/90-forward.conf
```

### Test Logging

```bash
docker exec aptl-reverse logger "TEST: Manual log entry"
```

### Tool Verification

```bash
# Check installed tools
docker exec aptl-reverse radare2 -version
docker exec aptl-reverse yara --version
docker exec aptl-reverse su - labadmin -c "floss --version"
```

### Service Issues

```bash
docker exec aptl-reverse systemctl list-units --failed
```