# MCP Integration

AI agents control lab containers via Model Context Protocol servers.

## Architecture

```mermaid
flowchart TD
    A[AI Agent] --> B[MCP Client]
    B --> C[Red Team MCP]
    B --> D[Blue Team MCP]
    
    C --> E[Kali Container<br/>172.20.0.30]
    D --> F[Wazuh Manager API<br/>172.20.0.10:55000]
    D --> G[Wazuh Indexer API<br/>172.20.0.12:9200]
    
    E --> H[Security Tools<br/>nmap, hydra, etc]
    F --> I[Alerts & Rules]
    G --> J[Log Search]
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

## Setup

Build both MCP servers and configure your AI client to connect. 

See implementation details:
- [Red Team MCP](../../mcp-red/README.md)
- [Blue Team MCP](../../mcp-blue/README.md)

## Usage

**Red Team:**
- Display lab network information
- Execute commands on Kali container

**Blue Team:**
- Query security alerts
- Search historical logs  
- Create detection rules
- Get SIEM status