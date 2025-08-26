# Minetest Client Container

The Minetest client container provides a platform for memory scanning operations and game client activities.

## Container Configuration

- **Base Image**: rockylinux:9
- **Packages**: minetest, gameconqueror, xrdp
- **User**: `labadmin` with sudo privileges
- **SSH**: Key-based authentication only (port 22, mapped to host 2025)

See [containers/minetest-client/Dockerfile](../../containers/minetest-client/Dockerfile) for complete build configuration.

## Network Access

- **Container IP**: 172.20.0.23
- **SSH Access**: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2025`

## MCP Integration

AI agents control this container via [Minetest Client MCP](../../mcp-minetest-client/README.md).

- **Tools**: `mc_client_run_command`, `mc_client_create_session`, etc.
- **Access Method**: SSH with key authentication
- **Tool Prefix**: `mc_client_*` to avoid conflicts
