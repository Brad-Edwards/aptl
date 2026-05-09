# ADR-027: Red Team Structured Logging Boundary

## Status

accepted

## Date

2026-05-09

## Context

AI agents execute arbitrary red-team commands through the Kali MCP server.
Existing Kali telemetry is split across:

- Wazuh-forwarded bash command history and `kali_redteam_rules.xml`
- MCP tool spans emitted through `aptl-mcp-common` OpenTelemetry wrappers
- SDL and detection models that already use OCSF-aligned names such as
  `product_name`, `analytic_uid`, and `severity_id`

Issue #162 adds OCSF-shaped red-team activity events for SIEM correlation.
The main design risk is creating a second command execution path, second
schema vocabulary, or second redaction/error-handling policy beside the common
MCP infrastructure.

## Decision

Red-team structured logging is a SIEM event boundary attached to MCP command
execution, not a replacement for OpenTelemetry tracing and not a new command
runner.

Implementations must:

- Reuse the `aptl-mcp-common` SSH command tool boundary for commands executed
  through MCP. Classification and metadata extraction may be enabled only for
  red-team/Kali tools, but command execution itself remains in the common
  handler/session infrastructure.
- Keep OpenTelemetry spans as observability data and OCSF red-team records as
  Wazuh/OpenSearch SIEM data. A single command may produce both, but neither
  format should be derived by scraping the other.
- Use OCSF field names consistently with the Python detection and attack
  models. In particular, keep `severity_id` on the OCSF 0-6 scale already used
  by `src/aptl/core/detection.py` and `src/aptl/core/attacks.py`.
- Treat the red-team taxonomy document as the human-readable source of truth
  for supported activity classes, MITRE mappings, required fields, and fallback
  behavior. TypeScript classifier/extractor tables should mirror that taxonomy,
  not invent competing labels.
- Emit a generic OCSF Process Activity record for unclassified commands rather
  than failing command execution or dropping the event entirely.
- Make SIEM logging best-effort. Classification, extraction, serialization, or
  transport failures must be visible on stderr/telemetry but must not prevent
  the requested MCP command from running or returning its result.
- Reuse the shared TypeScript redaction policy from
  `mcp/aptl-mcp-common/src/redaction.ts` at every serialization boundary that
  can contain command lines, outputs, errors, usernames, tokens, passwords,
  cookies, API keys, or private key material.

## Guardrails

- Do not log secret values to SIEM. For credential-oriented commands, record
  credential type, username/account when safe, and redaction markers or hashes
  where needed for correlation; do not preserve plaintext passwords, bearer
  tokens, cookies, API keys, private keys, or wordlist contents.
- Do not duplicate the `SeverityId` concept with incompatible numeric values.
  If TypeScript needs constants, name them as OCSF severity IDs and keep their
  values aligned to the Python enum.
- Do not parse command strings by splitting on whitespace alone. Compound
  commands, quotes, pipes, redirects, IPv6 addresses, CIDRs, and port ranges
  are part of the required input space.
- Do not couple taxonomy classification to Wazuh rule IDs. OCSF
  `class_uid`/`activity_id`/MITRE mappings describe the red action; Wazuh rule
  IDs describe downstream detection and alerting.
- Do not replace the existing Kali Wazuh agent, bash-history ingestion, or
  low-level `kali_redteam_rules.xml` until the OCSF path is proven to cover
  equivalent reconstruction needs.

## Consequences

### Positive

- Command execution, sessions, timeout handling, and MCP response shape remain
  centralized in `aptl-mcp-common`.
- Red-team events and detection events can correlate through shared OCSF and
  MITRE vocabulary without forcing tracing data into SIEM schemas.
- Logging failures degrade gracefully and cannot break red-team workflows.
- Secret handling follows the existing cross-language telemetry guardrail.

### Negative

- `aptl-mcp-common` needs a narrow extension point for post-command SIEM event
  emission, or `mcp-red` needs a wrapper that delegates back to common handlers.
- The first implementation must keep the taxonomy document and TypeScript
  tables in sync until a generated-schema path exists.

### Non-Goals

- Full shell AST interpretation.
- Complete OCSF coverage for every red-team tool.
- Replacing detection scoring, Wazuh rules, OpenTelemetry spans, or existing
  raw archive indexing.
- Logging non-MCP manual shell activity beyond the existing Kali bash-history
  and Wazuh-agent path.
