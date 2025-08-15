# APTL Wazuh Blue Team MCP Server

Model Context Protocol (MCP) server for AI-powered blue team operations using Wazuh SIEM in the APTL environment.

## Overview

This MCP server provides AI agents with secure access to Wazuh SIEM operations for defensive security analysis and investigation. It interfaces with the Wazuh API and OpenSearch indexer to enable automated threat hunting, alert analysis, and detection rule creation.

## Features

- **wazuh_info**: Get information about the Wazuh SIEM stack
- **query_alerts**: Search processed security alerts with filters  
- **query_logs**: Search raw log data before rule processing
- **create_detection_rule**: Create custom Wazuh detection rules

## Configuration

The server reads configuration from `wazuh-api-config.json` which contains actual deployment settings from docker-compose.yml:

```json
{
  "wazuh": {
    "manager": {
      "host": "172.20.0.10",
      "api_port": 55000,
      "api_username": "wazuh-wui",
      "api_password": "MyS3cr37P450r.*-"
    },
    "indexer": {
      "host": "172.20.0.12",
      "port": 9200,
      "username": "admin", 
      "password": "SecretPassword"
    }
  }
}
```

## Installation

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Test with MCP inspector
npm run inspector
```

## Usage

### With Cursor IDE

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "aptl-blue-team": {
      "command": "node",
      "args": ["./mcp-blue/build/index.js"],
      "cwd": ".",
      "env": {
        "WAZUH_API_CONFIG": "./mcp-blue/wazuh-api-config.json"
      }
    }
  }
}
```

### Example AI Agent Commands

```typescript
// Get SIEM information
await mcp.wazuh_info();

// Search for alerts in last hour
await mcp.query_alerts({ time_range: "1h", min_level: 5 });

// Search logs for specific term
await mcp.query_logs({ time_range: "6h", search_term: "sudo" });

// Create detection rule
await mcp.create_detection_rule({
  rule_xml: '<rule id="100300" level="8">...</rule>',
  rule_description: "Detect suspicious admin activity"
});
```

## Safety Controls

- **Query Validation**: All parameters validated against schema
- **Network Restrictions**: Only lab network IPs allowed
- **Rate Limiting**: Configurable query limits
- **Audit Logging**: All operations logged for review
- **Rule Validation**: XML rules validated for safety

## Architecture

```
[AI Agent] <-> [MCP Client] <-> [Blue Team MCP] <-> [Wazuh API/Indexer]
                                      |
                                      v
                              [Activity Logging]
```

## Development

```bash
# Watch mode for development
npm run watch

# Run tests  
npm test

# Type checking
npx tsc --noEmit
```