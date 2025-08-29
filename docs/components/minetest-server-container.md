# Minetest Server Container

The Minetest server container provides a platform for memory scanning operations and game server activities.

## Container Configuration

- **Base Image**: rockylinux:9
- **Packages**: minetest, gameconqueror, xrdp
- **User**: `labadmin` with sudo privileges
- **SSH**: Key-based authentication only (port 22, mapped to host 2024)

See [containers/minetest-server/Dockerfile](../../containers/minetest-server/Dockerfile) for complete build configuration.

## Network Access

- **Container IP**: 172.20.0.24
- **SSH Access**: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2024`

## MCP Integration

AI agents control this container via [Minetest Server MCP](../../mcp-minetest-server/README.md).

- **Tools**: `mc_server_run_command`, `mc_server_create_session`, etc.
- **Access Method**: SSH with key authentication
- **Tool Prefix**: `mc_server_*` to avoid conflicts
