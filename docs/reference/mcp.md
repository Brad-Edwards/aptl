# MCP Reference

APTL's Model Context Protocol servers let an authorized AI client operate the
red- and blue-team surfaces realized by a scenario. `aptl lab start` builds the
artifacts needed by that scenario and creates or updates the project-private
`.mcp.json` client configuration.

Start a project-aware MCP client from the lab project directory. Existing
client entries are preserved when APTL updates its managed entries. Treat
`.mcp.json` as a secret-bearing generated file: it can contain API credentials,
resolved ports, and transport settings.

## Server Availability

| Artifact | Generated client entry | Tool prefix | Default client config | Target |
| --- | --- | --- | --- | --- |
| `mcp-casemgmt` | `aptl-casemgmt` | `cases` | yes | TheHive cases, observables, and analyzers |
| `mcp-indexer` | `aptl-indexer` | `indexer` | yes | Wazuh Indexer search and index operations |
| `mcp-network` | `aptl-network` | `network` | yes | Network IDS observations exposed through the lab APIs |
| `mcp-red` | `aptl-red` | `kali` | yes | Kali information, commands, and bounded sessions |
| `mcp-reverse` | `aptl-reverse` | `reverse` | no | Optional reverse-engineering container sessions |
| `mcp-soar` | `aptl-soar` | `soar` | yes | Shuffle workflow and response operations |
| `mcp-threatintel` | `aptl-threatintel` | `threatintel` | yes | MISP threat-intelligence operations |
| `mcp-wazuh` | `aptl-wazuh` | `wazuh` | yes | Wazuh manager alerts, agents, and rules |

The table distinguishes three separate facts:

1. A **built artifact** exists in the released project assets.
2. A **generated client entry** is present only when APTL configures that
   server for the project and realized scenario.
3. An **advertised tool** is the fully qualified name returned by the connected
   server.

Do not treat the artifact list as proof that every server is active. The
optional reverse server, for example, is built but is absent from the default
client configuration unless the realized scenario provides its target.

## Tool Names And Behavior

Tool names use the server's prefix. SSH-backed servers advertise names such as
`kali_info`, `kali_run_command`, `kali_interactive_session`, and
`kali_get_session_output`; `run_command` by itself is not an APTL tool name.
API-backed servers advertise prefixed information, query, and action tools such
as `wazuh_api_info` or a server-specific qualified query name.

The connected server's tool list and input schema are authoritative for the
installed release. Tool availability can vary with the scenario, target
configuration, and server type. An unavailable target returns a bounded error;
the client must not bypass that result with direct credentials or an
undocumented network call.

## Setup And Verification

The normal path is automatic:

```shell
aptl lab start --scenario <id>
aptl lab status
```

After a successful or usable startup, open the client from the project root and
inspect its connected server and tool list. A simple read-only information
tool, such as `kali_info`, is a safer first check than a command or mutation.

Contributors can rebuild the tracked server artifacts without restarting the
lab:

```shell
./mcp/build-all-mcps.sh
```

That script is a source-project maintenance surface. Released-package users
normally let `aptl lab start` own the build and generated configuration.

## Security Boundary

- Keep `.env`, `.mcp.json`, private keys, bearer values, and tool responses
  containing target data out of issues and shared transcripts.
- Use the generated TLS and authentication settings. Do not disable certificate
  verification or replace authenticated API tools with direct calls.
- Run tools only against the selected APTL project and systems you are
  authorized to test.
- Use `aptl lab info` and the generated configuration for runtime endpoints;
  ports and available targets can change with realization.

For implementation architecture, see [MCP Integration](../components/mcp-integration.md).
