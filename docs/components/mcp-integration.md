# MCP Integration Architecture

APTL uses Model Context Protocol servers as scenario-aware adapters between an
authorized AI client and the red- or blue-team systems in a realized lab.

For operator setup, availability, and supported tool naming, use the
[MCP reference](../reference/mcp.md). This page explains the component boundary
without duplicating the generated runtime configuration.

## Runtime Flow

```mermaid
flowchart LR
    Client[Project-aware MCP client]
    Config[Generated private client config]
    Servers[Scenario-enabled MCP servers]
    Targets[Realized lab targets and APIs]

    Client --> Config
    Config --> Servers
    Servers --> Targets
```

`aptl lab start` realizes the scenario before it updates `.mcp.json`. This
ordering lets APTL include only supported servers, inject generated credentials,
and use runtime-resolved ports. A server artifact in the project tree does not
prove that its target exists in the current scenario.

## Server Families

SSH-backed servers use `aptl-mcp-common` for connection pooling, bounded
sessions, tool definition generation, error handling, telemetry, and
redaction. API-backed servers use the common authenticated HTTP/TLS boundary
and their declared query or action configurations.

Every server owns a `toolPrefix`. The common generators apply that prefix to
the advertised tool name, preventing collisions when several servers expose a
similar capability. The connected server remains the authority for its exact
tool list and input schemas.

## Configuration Boundary

The tracked `docker-lab-config.json` files describe server identity, prefix,
target type, and non-secret transport shape. The generated `.mcp.json` binds
those definitions to one realized project and can contain credentials. Keep it
private and let APTL update managed entries; do not turn it into checked-in
documentation or a shared template.

The optional reverse-engineering server demonstrates the artifact-versus-
availability distinction: APTL builds it with the other server artifacts, but
does not add it to the default client configuration when the scenario has no
reverse-engineering target.

## Development

Contributors can rebuild every server with:

```shell
./mcp/build-all-mcps.sh
```

Changes under `mcp/aptl-mcp-common` affect every dependent server and require a
complete dependent rebuild and test sweep. Operator workflows should use
`aptl lab start`, which owns build, realization, credentials, and generated
client configuration together.
