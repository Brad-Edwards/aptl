# MCP Integration

AI agents control lab containers via Model Context Protocol servers.

## Architecture

```mermaid
flowchart TD
    A[AI Agent] --> B[MCP Client]
    B --> C[Red Team MCP]
    B --> D[Blue Team MCP]
    B --> E[Minetest Client MCP]
    B --> F[Minetest Server MCP]
    
    C --> G[Kali Container<br/>172.20.0.30]
    D --> H[Wazuh Manager API<br/>172.20.0.10:55000]
    D --> I[Wazuh Indexer API<br/>172.20.0.12:9200]
    E --> J[Minetest Client<br/>172.20.0.23]
    F --> K[Minetest Server<br/>172.20.0.21]
    
    G --> L[Security Tools<br/>nmap, hydra, etc]
    H --> M[Alerts & Rules]
    I --> N[Log Search]
    J --> O[Memory Scanning<br/>gameconqueror]
    K --> P[Memory Scanning<br/>gameconqueror]
```

## MCP Servers

**Red Team MCP** (`/mcp-red`):

- SSH access to Kali container
- Tools: `kali_info`, `run_command`
- Target: 172.20.0.30

**Blue Team MCP** (`/mcp-blue`):

- Wazuh SIEM API access
- Tools: Alert queries, log search, rule creation
- APIs: Manager (55000), Indexer (9200)

**Minetest Client MCP** (`/mcp-minetest-client`):

- SSH access to minetest client container
- Tools: `mc_client_*` (run_command, create_session, etc.)
- Target: localhost:2025

**Minetest Server MCP** (`/mcp-minetest-server`):

- SSH access to minetest server container  
- Tools: `mc_server_*` (run_command, create_session, etc.)
- Target: localhost:2024

## Setup

Build both MCP servers and configure your AI client to connect.

See implementation details:

- [Red Team MCP](../../mcp-red/README.md)
- [Blue Team MCP](../../mcp-blue/README.md)
- [Minetest Client MCP](../../mcp-minetest-client/README.md)
- [Minetest Server MCP](../../mcp-minetest-server/README.md)

## Usage

**Red Team:**

- Display lab network information
- Execute commands on Kali container

**Blue Team:**

- Query security alerts
- Search historical logs  
- Create detection rules
- Get SIEM status
