# Kali Red Team Container

The Kali Linux container provides an attack platform for AI agents and manual security testing. All commands are logged to Wazuh SIEM.

## Container Configuration

- **Base Image**: kalilinux/kali-last-release:latest
- **Tools**: kali-linux-core, kali-tools-top10 (nmap, hydra, metasploit, etc.)
- **User**: `kali` with sudo privileges
- **SSH**: Key-based authentication only (port 22, mapped to host 2023)

See [containers/kali/Dockerfile](../../containers/kali/Dockerfile) for build details.

## Network Access

The Kali container is multi-homed across three networks:

| Network | IP | Purpose |
|---------|----|---------|
| aptl-redteam | 172.20.4.30 | Primary red team network |
| aptl-dmz | 172.20.1.30 | Access to DMZ services |
| aptl-internal | 172.20.2.35 | Access to internal targets |

SSH from host: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## MCP Integration

The Red Team MCP server (`mcp/mcp-red`) enables AI agents to control Kali tools. All tools use the `kali_` prefix.

**Available tools:**

| Tool | Description |
|------|-------------|
| `kali_info` | Display lab network and container info |
| `kali_run_command` | Execute a command on Kali |
| `kali_interactive_session` | Start an interactive SSH session |
| `kali_background_session` | Start a background session |
| `kali_session_command` | Run command in an existing session |
| `kali_list_sessions` | List active sessions |
| `kali_close_session` | Close a specific session |
| `kali_get_session_output` | Get output from a session |
| `kali_close_all_sessions` | Close all sessions |

Build: `cd mcp/mcp-red && npm install && npm run build`

See [MCP Integration](mcp-integration.md) for AI client configuration.

## SIEM Integration

Red team activities are logged to Wazuh SIEM via Wazuh agent:

- **Agent Group**: `kali-redteam`
- **Logs**: CLI commands, authentication events, system logs
- **Destination**: Wazuh Manager (port 1514)

## Access

```bash
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023
```
