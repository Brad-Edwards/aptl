# Reverse Engineering Container

The reverse engineering container provides a platform for binary analysis and malware reverse engineering operations.

## Container Configuration

- **Base Image**: ubuntu:22.04
- **Tools**: radare2, binutils, yara, floss, capa, upx-ucl, osslsigncode
- **User**: `labadmin` with sudo privileges
- **SSH**: Key-based authentication only (port 22, mapped to host 2027)

See [containers/reverse/Dockerfile](../../containers/reverse/Dockerfile) for complete build configuration.

## Network Access

- **Container IP**: 172.20.0.27
- **SSH Access**: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027`

## MCP Integration

AI agents control this container via [Reverse Engineering MCP](../../mcp/mcp-reverse/README.md).

- **Tools**: `reverse_run_command`, `reverse_info`, etc.
- **Access Method**: SSH with key authentication
- **Tool Prefix**: `reverse_*` to avoid conflicts

## SIEM Integration

Reverse engineering activities are logged to Wazuh SIEM via Wazuh agent:

- **Agent Group**: `reverse`
- **Logs**: CLI commands, analysis activities, system logs
- **Destination**: Wazuh Manager (172.20.0.10:1514)
- **Purpose**: Blue team analysis and detection training
