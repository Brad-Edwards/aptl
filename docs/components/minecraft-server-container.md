# Minecraft Server Container

The Minecraft server container provides a Minecraft server environment for testing and demonstration purposes.

## Container Configuration

- **Base Image**: rockylinux:9
- **Packages**: java-17-openjdk, wget
- **User**: `labadmin` with sudo privileges
- **SSH**: Key-based authentication only (port 22, mapped to host 2026)

See [containers/minecraft-server/Dockerfile](../../containers/minecraft-server/Dockerfile) for complete build configuration.

## Network Access

- **Container IP**: 172.20.0.26
- **SSH Access**: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2026`
- **Minecraft Port**: 25565

## MCP Integration

AI agents control this container via [Minecraft Server MCP](../../mcp-minecraft-server/README.md).

- **Tools**: `mc_server_run_command`, `mc_server_create_session`, etc.
- **Access Method**: SSH with key authentication  
- **Tool Prefix**: `mc_server_*` to avoid conflicts
