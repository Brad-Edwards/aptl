# APTL Kali MCP Server

This MCP (Model Context Protocol) server provides AI assistants with access to a Kali Linux environment for red team operations in the APTL lab.

## Current Status

This MCP server currently supports Docker-based Kali Linux containers for local development and testing. Future versions will add support for connecting to EC2-based Kali instances.

## Features

- Execute commands in Kali Linux environment
- File access (read/write) capabilities
- Interactive session support for tools like Metasploit
- Pre-installed security tools including:
  - Web exploitation: Burp Suite, SQLMap, Dirb, Nikto
  - Network tools: Nmap, Wireshark, tcpdump
  - Password cracking: Hydra, John the Ripper, Hashcat
  - Forensics: Binwalk, Foremost, ExifTool
  - Reverse engineering: GDB, Radare2
  - Exploitation: Metasploit Framework

## Installation

1. Install dependencies:

   ```bash
   cd red_team/kali-mcp
   npm install
   ```

2. Build the project:

   ```bash
   npm run build
   ```

## Configuration

### For Docker (Current)

The MCP server uses Docker to run a Kali Linux container. Configure in your MCP settings:

```json
{
  "mcpServers": {
    "aptl-kali": {
      "command": "node",
      "args": ["/path/to/aptl/red_team/kali-mcp/build/index.js"],
      "env": {
        "CONTAINER_NAME": "kali-ctf",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### For EC2 (Future)

Future versions will support connecting to EC2 Kali instances:

```json
{
  "mcpServers": {
    "aptl-kali": {
      "command": "node",
      "args": ["/path/to/aptl/red_team/kali-mcp/build/index.js"],
      "env": {
        "CONNECTION_TYPE": "ssh",
        "KALI_HOST": "your-kali-instance-ip",
        "KALI_USERNAME": "kali",
        "PRIVATE_KEY_PATH": "~/.ssh/purple-team-key",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

## Usage

Once configured, the AI assistant can use the following tools:

- `execute_command` - Run commands in the Kali environment
- `read_file` - Read files from the Kali environment
- `write_file` - Write files to the Kali environment
- `create_session` - Create interactive terminal sessions
- `send_input` - Send input to interactive sessions
- `get_output` - Get output from interactive sessions
- `list_sessions` - List active sessions
- `terminate_session` - Close interactive sessions

## Development

To run the server locally:

```bash
./scripts/start.sh
```

## Future Enhancements

1. **SSH Connection Support**: Add ability to connect to EC2 Kali instances
2. **Connection Abstraction**: Create a unified interface for both Docker and SSH connections
3. **Enhanced Security**: Add authentication and authorization mechanisms
4. **Session Persistence**: Maintain session state across MCP server restarts
