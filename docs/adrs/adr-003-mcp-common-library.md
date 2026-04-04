# ADR-003: MCP Common Library with Config-Driven Server Generation

## Status

accepted

## Date

2025-08-30

## Context

By v2.0.5, APTL had two MCP (Model Context Protocol) servers — `mcp-red` (Kali) and `mcp-blue` (Wazuh) — that allowed AI agents to control lab containers and query the SIEM. Both servers were standalone TypeScript projects with significant code duplication:

### Problems

1. **Duplicated SSH handling**: Each server implemented its own SSH connection logic — creating connections, managing sessions, handling timeouts, parsing output. The connection management code was nearly identical.
2. **Identical entry points**: Every `src/index.ts` was the same boilerplate: import config, create server, register tools, start listening. Copy-paste across servers led to wrong doc comments (e.g., `mcp-reverse` said "APTL Kali Red Team MCP Server").
3. **`any`-typed tool arguments**: All MCP tool handlers received `args: any` and cast internally with `as`. No compile-time safety. The MCP SDK validates args against JSON Schema at runtime, but TypeScript couldn't catch type errors during development.
4. **No shared HTTP client**: API-based servers (Wazuh, indexer) each implemented their own HTTP request handling with inconsistent error handling and a process-global `NODE_TLS_REJECT_UNAUTHORIZED = '0'` that disabled SSL verification for all outbound requests.

Adding a third MCP server meant copying one of the existing servers and modifying it — propagating all these problems. The reverse engineering MCP server (`mcp-reverse`) was created this way and inherited the SSH prefix bug and wrong doc comment.

### Scale

When this decision was made, there were 2-3 MCP servers. The architecture needed to support 8+ servers (Kali, Wazuh, indexer, reverse, MISP, TheHive, Shuffle, Suricata) as the SOC stack grew.

## Decision

Create `mcp/aptl-mcp-common/` as a shared TypeScript library that all MCP servers depend on. The library provides:

### Core Components

1. **`PersistentSession`** (ssh.ts): Long-lived SSH session management with command queuing, delimiter-based output parsing, buffer overflow protection, keepalive, and per-command timeouts. See [ADR-004](adr-004-persistent-ssh-sessions.md) for the full session architecture.

2. **`SSHConnectionManager`** (ssh.ts): Connection pool managing multiple `PersistentSession` instances. Handles connection lifecycle, session creation/destruction, and metadata tracking.

3. **`HTTPClient`** (http.ts): Shared HTTP client for API-based MCP servers. Uses per-request `https.Agent` with `rejectUnauthorized: false` (instead of mutating `process.env`) for self-signed certificates in the lab environment.

4. **`createMCPServer(config)`** (server.ts): Factory function that generates a fully configured MCP server from a `docker-lab-config.json` file. Registers SSH tool definitions, API tool definitions, and their handlers based on the config.

5. **`startServer(callerMetaUrl)`** (index.ts): Standard entry point for all APTL MCP servers. Loads config relative to the calling module's directory, creates the server, and starts it. A new MCP server's `src/index.ts` is now ~4 lines:

   ```typescript
   import { startServer } from 'aptl-mcp-common';
   startServer(import.meta.url);
   ```

6. **Typed argument interfaces** (tools/handlers.ts): Named interfaces (`RunCommandArgs`, `SessionCommandArgs`, `ListSessionsArgs`, etc.) for all 10 SSH tool handlers and 3 API tool handlers. Replaces `args: any` with compile-time type checking.

7. **Shell formatters** (shells.ts): Strategy pattern for shell-specific command formatting — bash, sh, PowerShell, cmd. Each formatter knows how to set environment variables, change directories, and format commands for its shell.

### Config-Driven Architecture

Each MCP server is defined by a `docker-lab-config.json` file containing:

- Server name and description
- Target container connection details (host, port, username, key path)
- SSH tool definitions (if applicable)
- API tool definitions with endpoint templates (if applicable)
- Shell type (bash, sh, powershell, cmd)

The `createMCPServer()` factory reads this config and generates the full server — tool definitions, handlers, connection management — without any server-specific code. Adding a new container to the MCP layer requires only a new config file and a 4-line `index.ts`.

### Build System

All MCP servers are built via `mcp/build-all-mcps.sh`, which iterates through every `mcp/mcp-*` directory and runs `npm run build`. The common library is built first as a dependency.

## Consequences

### Positive

- **DRY**: SSH handling, HTTP clients, entry points, tool registration — all written once
- **Type safety**: Named argument interfaces catch type errors at compile time. The `queryConfig.endpoint` → `queryConfig.url` bug was found during the typed args migration.
- **Consistency**: All 8 MCP servers behave identically for connection management, error handling, and response formatting
- **Rapid server creation**: New MCP server = `docker-lab-config.json` + 4-line `index.ts`. The SOC stack MCP servers (MISP, TheHive, Shuffle, Suricata) were created using this pattern.
- **Centralized fixes**: Bug fixes to SSH session handling or HTTP requests propagate to all servers automatically

### Negative

- **Coupling**: All servers depend on the common library. A breaking change requires updating and rebuilding all servers.
- **Abstraction overhead**: The config-driven approach is powerful but less transparent than explicit code. Debugging requires understanding the factory pattern and config schema.
- **Monorepo structure**: The `mcp/` directory contains 9 npm packages (1 library + 8 servers) without a workspace manager like Turborepo or Nx. Build ordering depends on `build-all-mcps.sh`.

### Risks

- Config schema evolution: Adding new tool types or connection methods requires updating the common library's config parser, factory, and handler generators
- The common library is a single point of failure — a bug in `PersistentSession` affects all SSH-based MCP servers simultaneously
