# APTL Kali MCP Server

Model Context Protocol server for APTL Kali Linux red team operations

This is a TypeScript-based MCP server that provides secure access to red team operations in the Advanced Purple Team Lab (APTL) environment. It integrates directly with your Terraform-deployed lab infrastructure.

## Features

### Configuration

- **Terraform Integration**: Automatically reads configuration from `terraform output`
- **Dynamic Discovery**: Finds Terraform root directory by searching upward
- **Environment Override**: Use `TERRAFORM_ROOT` to specify custom terraform directory
- **Secure SSH**: Uses your actual SSH keys and credentials from Terraform

### Tools

- `kali_info` - Get information about the Kali Linux instance
  - Returns IP addresses, SSH details, and lab configuration
  - Shows when Kali is enabled/disabled in the lab

- `run_command` - Execute commands on any lab instance
  - **Auto-detection**: Automatically determines SSH credentials based on target IP
  - **Multi-target**: Supports SIEM, victim, and Kali instances
  - **Security**: Only allows commands on lab network ranges
  - **Error handling**: Graceful failure when lab isn't deployed

### Security

- **Network validation**: Commands restricted to lab CIDR ranges
- **SSH key management**: Uses actual keys from Terraform configuration
- **Connection pooling**: Efficient SSH connection reuse
- **Audit logging**: All operations logged for security

## Architecture

The MCP server operates as a bridge between LLM agents and your lab infrastructure:

```
LLM Agent → MCP Server → Terraform Output → SSH → Lab Instances
```

1. **Configuration Loading**: Reads live infrastructure state from `terraform output`
2. **Target Validation**: Ensures commands only run on lab instances
3. **Credential Auto-detection**: Uses correct SSH keys/users per instance
4. **Command Execution**: Secure SSH execution with connection pooling

## Development

Install dependencies:

```bash
npm install
```

Build the server:

```bash
npm run build
```

For development with auto-rebuild:

```bash
npm run watch
```

## Installation

To use with Claude Desktop, add the server config:

On MacOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
On Windows: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "kali-red-team": {
      "command": "/path/to/aptl/red_team/kali_mcp/build/index.js"
    }
  }
}
```

## Prerequisites

1. **Deployed Lab**: Run `terraform apply` to deploy the APTL infrastructure
2. **SSH Keys**: Ensure your SSH private key matches the `key_name` in `terraform.tfvars`
3. **Terraform**: Must be available in PATH for the MCP to read outputs

## Usage Examples

**Get lab information:**

```
Use the kali_info tool to see current lab configuration
```

**Run commands on specific targets:**

```
Use run_command with target="10.0.1.10" to run commands on SIEM
Use run_command with target="10.0.1.20" to run commands on victim
Use run_command with target="10.0.1.30" to run commands on Kali
```

### Debugging

Since MCP servers communicate over stdio, debugging can be challenging. Use the [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npm run inspector
```

The Inspector provides a web interface for testing MCP tools and debugging issues.

## Error Handling

- **Lab not deployed**: Graceful error messages when `terraform output` fails
- **SSH failures**: Clear error reporting for connection issues
- **Invalid targets**: Security validation prevents commands on unauthorized networks
- **Missing keys**: Helpful messages when SSH keys aren't found
