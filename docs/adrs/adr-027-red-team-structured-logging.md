# ADR-027: Red Team Structured Logging Boundary

## Status

accepted (amended 2026-05-17 by [ADR-033](adr-033-agent-reasoning-trace-boundary.md))

## Date

2026-05-09 (amended 2026-05-17)

## Status update — 2026-05-17

The SIEM-transport portion of this ADR — rsyslog-to-Wazuh forwarding
from the Kali container, Wazuh-agent-on-Kali ingestion, and the
`kali_redteam_rules.xml` decoder loaded by the Wazuh manager — is
**superseded by ADR-033** under the non-contamination principle. Red
activity must not bleed into the blue defensive stack's awareness via
the SIEM, because that injection inflates blue's artificial picture
of red and contaminates purple-loop experiments.

What stays from this ADR is **the OCSF schema work**:

- The classifier (`mcp/mcp-red/src/classifier.ts`) and extractor
  (`mcp/mcp-red/src/extractor.ts`) tables.
- The activity taxonomy with MITRE technique/tactic mappings.
- `SeverityId` 0–6 aligned with `src/aptl/core/detection.py`.
- The `OcsfRedTeamRecord` shape including the `aptl` envelope.
- The `postToolHook` architecture for emitting records.
- Cross-language redaction at the serialization boundary (ADR-029).
- Best-effort guarantee: classification / extraction / sink failures
  do not break tool execution.
- Raw-session outcome handling: the Kali `postToolHook` must use the effective
  mode surfaced in the `session_command` result envelope. The request argument
  `raw` is only a per-call override and does not reveal inherited raw mode from
  a session created with raw mode enabled.

What changes is **the sink**:

- The default sink composite now writes to stderr (with `[OCSF]`
  sentinel — local dev visibility) AND to a per-run JSONL at
  `<state>/runs/<trace_id>/mcp-side/ocsf.jsonl` — never to a SIEM.
- `mcp/mcp-red/src/logger.ts` exports `localOcsfJsonlSink(env)` and
  `defaultRedTeamSinks(env)`; the existing `stderrJsonlSink` is
  retained as a building block but no longer the default by itself.
- The `SiemSink` type name is intentionally kept to avoid a churning
  rename across tests; the *behaviour* under that name is
  non-SIEM-bound. A future ADR may rename the type if there is
  appetite.

The "Do not replace the existing Kali Wazuh agent, bash-history
ingestion, or low-level `kali_redteam_rules.xml` until the OCSF path
is proven to cover equivalent reconstruction needs" guardrail
(below) is reversed: those red-side SIEM pipes are removed as part
of ADR-033's implementation. The equivalent reconstruction surface
now lives in the per-run capture directory (PTY typescripts, pcaps,
auditd events, OCSF JSONL, tool-call JSONL), which is more complete
than the previous SIEM ingestion path.

Everything below this section is the original decision text,
preserved for historical context.

## Status update - 2026-05-18

For `*_session_command`, OCSF status must be derived from the effective command
mode and observed command outcome, not from request arguments alone. If the
`session_command` result envelope reports `session_mode: "raw"`, the OCSF
record must emit `status_id=0` / `status="Unknown"` even when the raw-mode SSH
result contains `exit_code: 0`.

This keeps the common MCP session layer as the source of truth for execution
mode and keeps `mcp-red` as a best-effort observer. Do not duplicate the common
session mode rules in `mcp-red`, do not parse session ids or query session state
from the logger, and do not let OCSF logging failures affect tool execution.

---

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
