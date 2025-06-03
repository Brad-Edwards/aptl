# Kali Linux MCP Server for CTF Challenges

This project provides an MCP (Model Context Protocol) server that gives AI assistants like Cursor or Cline access to a Kali Linux environment for CTF (Capture The Flag) challenges.

## Features

- Docker-based Kali Linux environment with pre-installed security tools
- OWASP Juice Shop CTF environment for testing and training
- MCP server for interfacing with the Kali environment
- Tools for executing commands in the Kali environment
- File access capabilities for reading and writing files
- Interactive session support for complex tools like Metasploit
- Isolated environment for security testing

## Prerequisites

- Node.js (v16+)
- Docker
- TypeScript
- MCP SDK

## Installation

1. Clone the repository:

   ```
   git clone <repository-url>
   cd aptl
   ```

2. Install dependencies:

   ```
   npm install
   ```

3. Build the project:

   ```
   npm run build
   ```

## Usage

### Starting the Server

1. Start the MCP server:

   ```
   npm start
   ```

   Or use the provided start script:

   ```
   ./scripts/start.sh
   ```

2. Configure your AI assistant (Cursor/Cline) to connect to the MCP server by adding the following to your MCP settings file:

   ```json
   {
     "mcpServers": {
       "kali-ctf": {
         "command": "node",
         "args": ["/path/to/aptl/build/index.js"],
         "env": {
           "CONTAINER_NAME": "kali-ctf"
         },
         "disabled": false,
         "autoApprove": []
       }
     }
   }
   ```

### Testing the Server

The `examples` directory contains several scripts and examples to help you test the MCP server:

1. **juice-shop-example.js** - A JavaScript example that demonstrates how to use APTL to interact with the OWASP Juice Shop CTF environment:

   ```
   node examples/juice-shop-example.js
   ```

2. **test-lookups.sh** - A shell script that demonstrates how to perform WHOIS and DNS lookups using the MCP server:

   ```
   ./examples/test-lookups.sh
   ```

3. **test-lookups.js** - A JavaScript example that shows how to use the MCP client SDK to interact with the server:

   ```
   node examples/test-lookups.js
   ```

4. **cursor-cline-example.md** - A markdown file with examples of how to use the MCP server through Cursor/Cline for various network reconnaissance tasks.

### OWASP Juice Shop CTF Environment

This project includes an OWASP Juice Shop CTF environment that can be used to test and train AI assistants on web application security challenges.

To start the CTF environment:

```
./scripts/ctf-setup.sh start
```

For more information about the CTF environment, see:

- [CTF Environment Documentation](docker/ctf/README.md)
- [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/)

The CTF environment includes:

- A deliberately vulnerable web application with progressive challenges
- Challenges ranging from simple reconnaissance to complex exploitation
- A scoring system to track progress
- Support for both interactive and non-interactive tools

### Available Tools

Once connected, the AI assistant will have access to the following tools:

1. **execute_command** - Execute a command in the Kali Linux environment

   ```
   Arguments:
   - command: The command to execute
   ```

2. **read_file** - Read a file from the Kali Linux environment

   ```
   Arguments:
   - path: Path to the file
   ```

3. **write_file** - Write content to a file in the Kali Linux environment

   ```
   Arguments:
   - path: Path to the file
   - content: Content to write
   ```

4. **create_session** - Create a new interactive terminal session

   ```
   Arguments:
   - name: Name for the session (optional)
   - workingDir: Working directory for the session (default: /ctf)
   - env: Environment variables for the session
   - shell: Shell to use (default: bash)
   - initialCommand: Command to run when the session starts
   ```

5. **send_input** - Send input to an interactive terminal session

   ```
   Arguments:
   - sessionId: ID of the session
   - input: Input to send to the session
   - endWithNewline: Whether to append a newline to the input (default: true)
   ```

6. **get_output** - Get output from an interactive terminal session

   ```
   Arguments:
   - sessionId: ID of the session
   - wait: Whether to wait for output if none is available (default: false)
   - timeout: Timeout in milliseconds when waiting for output (default: 5000)
   ```

7. **list_sessions** - List all active interactive terminal sessions

8. **terminate_session** - Terminate an interactive terminal session

   ```
   Arguments:
   - sessionId: ID of the session to terminate
   ```

### Available Resources

The MCP server also provides the following resources:

1. **kali://files/readme** - Information about the Kali CTF environment
2. **kali://files/{path}** - Access to files in the Kali environment

## Docker Container

The Kali Linux container includes the following tools:

- Web exploitation: burpsuite, sqlmap, dirb, nikto
- Network tools: nmap, wireshark, tcpdump
- Password cracking: hydra, john, hashcat
- Forensics: binwalk, foremost, exiftool
- Reverse engineering: gdb, radare2
- Cryptography: openssl
- Exploitation: metasploit-framework

## Development

### Project Structure

```
aptl/
├── docker/
│   ├── Dockerfile            # Kali Linux container configuration
│   ├── docker-compose.yml    # Docker Compose configuration for Kali and Juice Shop
│   └── ctf/                  # CTF environment configuration and documentation
│       └── README.md         # Documentation for the CTF environment
├── src/
│   ├── index.ts              # Main MCP server implementation
│   ├── tools/                # MCP tool implementations
│   │   ├── execute-command.ts # Command execution in Kali
│   │   ├── file-access.ts    # File operations in Kali
│   │   └── session-tools.ts  # Interactive session management
│   └── utils/                # Helper utilities
│       ├── docker-manager.ts # Docker container management
│       ├── session-manager.ts # Terminal session management
│       └── logger.ts         # Logging utility
├── scripts/
│   ├── setup.sh              # Environment setup script
│   ├── start.sh              # Server startup script
│   └── ctf-setup.sh          # CTF environment setup script
├── config/
│   └── mcp-settings.json     # MCP server configuration
├── docs/
│   └── design/
│       └── terminal_session_manager.md # Design pattern for interactive CLI sessions
├── examples/
│   ├── juice-shop-example.js # Example of using APTL with the Juice Shop CTF
│   ├── test-lookups.sh       # Shell script for testing whois and DNS lookups
│   ├── test-lookups.js       # JavaScript example using Docker directly
│   └── cursor-cline-example.md # Examples of using the MCP server through Cursor/Cline
└── README.md                 # Documentation
```

### Design Documentation

For detailed information about the architecture and design patterns used in this project, see:

- [Terminal Session Manager Design Pattern](docs/design/terminal_session_manager.md) - A robust pattern for enabling interactive CLI sessions through MCP

### Building from Source

1. Make changes to the TypeScript source code
2. Build the project:

   ```
   npm run build
   ```

3. Run the server:

   ```
   npm start
   ```

## Security Considerations

- This tool is to be used only for CTF challenges where automated tools are permitted.
- The user must have explicit permission to perform security testing on the target systems.
- The tool should not be used for unauthorized security testing or exploitation.

## License

MIT
