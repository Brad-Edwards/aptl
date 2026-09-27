# Participant workbench

The optional workbench uses the same packaged **full TechVault** deployment as
normal local `aptl lab start`. It requires neither a VM nor appliance metadata
for local use. [ADR-059](../adrs/adr-059-canonical-techvault-delivery-and-host-mcp-access.md)
extends ADR-049 with authenticated host CLI access; appliance delivery retains
its signed boundary and qualification gates.
The `techvault-participant-study` pack reuses this full deployment and binds
workbench access to its own exact acquired pack identity.

| Role | MCP servers | Browser surfaces |
| --- | --- | --- |
| `red` | `aptl-red` | Packaged guide and captured Kali command terminal |
| `blue` | `aptl-indexer`, `aptl-wazuh`, `aptl-network`, `aptl-threatintel`, `aptl-casemgmt`, `aptl-soar` | Guide, Wazuh, TheHive, MISP, Shuffle |

`guided-blue` remains available for the historical guided fixture. It is not
the full-TechVault delivery profile. The Kali surface is a command terminal
through the admitted red MCP, not a graphical remote desktop.

## Assembly and authorization

`create_local_workbench_app` consumes an enrolled `GuestDispatchBinding`, the
`LocalWorkbenchSettings` project/state paths, a fixed APTL executable, and a trusted browser
session verifier. The verifier returns `BrowserPrincipal(caller_id, profiles)`;
a boolean is rejected. Its caller and single role must match the enrolled,
unexpired grant. Every request checks live deployment identity, required
capture, revocation and, for appliances, fresh signed-boundary evidence.
`create_appliance_workbench_app` uses this same assembly and requires a binding.
Neither factory mounts the operator API or accepts participant-supplied
commands, service URLs, Docker endpoints, credentials or launch paths.

The guide comes from the installed pack. The Kali WebSocket uses the same
restricted MCP dispatcher as host clients. Blue browser services use explicit
`BrowserRoute` mappings: one dedicated `*.localhost` virtual host per service,
a fixed guest loopback upstream, and a role check before proxying HTTP or
WebSockets. The gateway retains service root paths, bounds connections and
messages, and removes the participant session cookie before proxying. Supply
a trusted TLS context for guest HTTPS services; the default verifies certificates.
The outer launcher owns browser session establishment, listener allocation,
DNS/Host routing and TLS termination.

The optional browser agent adapter is Claude Code. The management-side broker
supplies only its configured provider key; guest MCP service credentials never
enter the agent environment. Users of the **host** Claude Code or Codex CLI keep
provider authentication in their own host account. Browser agent use is not
required for the guide, terminal or service browser routes.

## MCP authority and capture

Generated browser agent configs invoke the fixed APTL dispatcher. Host client
configs invoke pinned OpenSSH. Both reach the same exact role/tool admission,
minimal guest-only service credential environment and bounded process lifetime.
Tools are verified against the canonical inventory before the initialization
reply. Client allowlists and hidden UI buttons do not substitute for this gate.

An admitted run ID is passed to common MCP capture even when normal lab startup
has no scenario-UI trace file. Agent records store correlation IDs, sizes and
hashes. The relay preserves canonical redaction and requires remote SSH closure;
unproved cleanup taints that instance generation and blocks further admission.
See [host MCP access](../reference/host-mcp-access.md) for enrollment, revocation,
client file ownership, wire limits and the downstream seat contract.
