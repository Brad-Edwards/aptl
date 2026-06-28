# ADR-045: Composite MCP Tool Orchestration Boundary

## Status

accepted

## Date

2026-06-28

## Context

ORC-003 / issue #477 asks the MCP layer to support composite tools: one MCP
tool call that performs a common multi-step operation such as running an nmap
scan, parsing its output, and returning a concise report.

The design risk is not the existence of another MCP tool. The risk is creating
a second command runner, second API client, second schema vocabulary, second
redaction policy, second run-artifact layout, or an implicit red/blue bridge
beside the already-established MCP boundary.

Existing architectural owners already cover most of the required surface:

- `mcp/aptl-mcp-common/src/server.ts` owns MCP server creation, tool
  registration, `traceToolCall()`, and the `postToolHook` boundary.
- `mcp/aptl-mcp-common/src/tools/definitions.ts` and `tools/handlers.ts` own
  SSH tool schemas, handler envelopes, session-id validation, and
  `SSHConnectionManager` use.
- `mcp/aptl-mcp-common/src/tools/api-definitions.ts`,
  `tools/api-handlers.ts`, `http.ts`, and `endpoint-url.ts` own API tool
  schemas, endpoint validation, auth, TLS, and HTTP errors.
- `mcp/mcp-red/src/index.ts`, `capture.ts`, `logger.ts`, `classifier.ts`, and
  `extractor.ts` own red-team command capture, OCSF records, command
  segmentation, and non-contaminating per-run sinks.
- `mcp/aptl-mcp-common/src/runs.ts`, `captures.ts`, and
  `src/aptl/core/runstore.py` own per-run artifact layout and identifier
  contracts.
- ADR-003, ADR-004, ADR-012, ADR-027, ADR-029, ADR-033, ADR-034, ADR-037,
  ADR-041, and ADR-042 already define the common MCP, SSH, telemetry,
  redaction, non-contamination, TLS, Docker, and capture boundaries.

## Decision

Composite MCP tools are **tool-boundary orchestrators over existing MCP common
primitives**, not a new workflow engine and not a new execution substrate.

A composite tool may expose a single MCP tool name and a compact result, but
its internal steps must reuse the same canonical surfaces that a manually
orchestrating agent would have used:

- SSH execution goes through `SSHConnectionManager` / `PersistentSession` and
  the existing handler response conventions.
- API calls go through `HTTPClient`, `resolveApiRequestUrl()`, per-query TLS
  and auth semantics, and the existing API handler envelope conventions.
- MCP request/response tracing stays under `traceToolCall()`.
- Red-team command-bearing steps stay visible to the red capture and OCSF
  path. A composite must not make internal shell commands disappear from
  `tool-calls.jsonl`, `ocsf.jsonl`, PTY tee, or Kali-side captures merely
  because the agent made one top-level tool call.
- Per-run artifacts stay under the existing run directory contract; new MCP
  sidecar report files, if any, belong under the `mcp-side` tree with
  restrictive permissions and ADR-029 redaction.

Composite tool registration should remain centralized in
`aptl-mcp-common`. Server-specific packages may opt into domain-specific
composites, but they must do so through a typed common registration seam rather
than by reimplementing MCP server startup, command execution, HTTP transport,
or telemetry.

The existing name-based context routing in `createMCPServer()` is too fragile
for composites that are neither plain SSH tools nor predefined API queries.
The extensibility seam is an explicit tool-kind/handler registry entry that
declares whether the handler needs SSH, HTTP, or both contexts. Do not encode
composite semantics in tool-name substrings or suffix collisions.

## Security Layers

- **MCP ingress schema:** every composite input must have a JSON Schema tool
  definition. Inputs such as target, CIDR, ports, timing, output format, and
  timeout must be typed and bounded. Do not accept free-form `extra_args`,
  shell fragments, or arbitrary command templates as composite parameters.
- **Domain validation:** command-building inputs must be parsed into
  allowlisted primitives before assembly. For scan-style composites, validate
  host/CIDR and port-range syntax, cap fan-out and timeout, and default to the
  configured lab network. Any future non-lab target allowance needs an explicit
  operator-facing policy seam; it must not be hidden in a convenience tool.
- **Command execution:** shell execution still uses the existing SSH session
  layer. Composite code must not spawn local `nmap`, `docker`, `curl`, or shell
  processes from the MCP host to bypass the lab container boundary. When a
  command string must be assembled for the remote shell, every user-controlled
  part must have been validated or safely quoted; never concatenate raw input.
- **Structured parsing:** parse machine-readable tool output when available
  (for example nmap XML or another structured format) instead of scraping
  human-formatted text with ad hoc regexes.
- **Secret handling:** arguments, command lines, responses, errors, OCSF
  fields, report artifacts, and traces pass through
  `mcp/aptl-mcp-common/src/redaction.ts` at the established boundaries. Do not
  add a composite-local sanitizer or weaken command redaction to preserve a
  prettier report.
- **Auth and TLS:** API-backed composite steps must reuse `HTTPClient`,
  `endpoint-url.ts`, `verify_ssl`, `ca_cert_path`, and per-query auth
  inheritance. API tokens and credentials stay in `.env` / MCP config
  substitution, not in tool arguments, process argv, report text, or errors.
- **Error envelopes:** use the existing MCP `{ success, ... }` JSON text
  response style and existing `SSHError` / HTTP error handling. A partial
  composite failure may report the failed step and sanitized diagnostics, but
  must not introduce another exception hierarchy or leak raw stderr, tokens,
  private keys, cookies, or full upstream response bodies.
- **Observability:** keep one top-level MCP span for the composite call and
  retain per-command/per-step evidence through the existing red capture,
  OCSF, PTY tee, and Kali-side capture paths. Observability failures remain
  best-effort and must not change command execution results.
- **Non-contamination:** red-side composites must not query Wazuh, Suricata,
  TheHive, MISP, Shuffle, or other blue/SOC APIs as a convenience report step.
  Blue/SOC composites may summarize defender-visible APIs. Any future purple
  composite that deliberately joins red evidence with blue observations needs a
  separate design because it crosses the ADR-033 experiment boundary.
- **Persistence and OS exposure:** composite report persistence, if added,
  uses existing per-run directories and restrictive modes. Do not write reports
  into the repo tree, `/tmp`, command-line arguments, unchecked Docker volumes,
  or long-lived process environment variables.

## Maintainability

Implementations must build on these incumbents:

- `LabConfig` loading and MCP `docker-lab-config.json` env substitution in
  `mcp/aptl-mcp-common/src/config.ts`.
- Tool definition and handler generation in `mcp/aptl-mcp-common/src/tools/*`.
- `SSHConnectionManager`, `PersistentSession`, effective session mode,
  session-id validation, and remote-close cleanup in `ssh.ts` and
  `tools/handlers.ts`.
- `HTTPClient`, `assertPathOnlyEndpoint()`, `resolveApiRequestUrl()`, and
  query-specific auth/TLS inheritance in `http.ts`, `endpoint-url.ts`, and
  `tools/api-handlers.ts`.
- `traceToolCall()` and shared redaction in `telemetry.ts` and `redaction.ts`.
- Red command classification, extraction, capture, and OCSF sinks in
  `mcp/mcp-red/src/*` for command-bearing Kali composites.
- Per-run path helpers and identifier validation in
  `mcp/aptl-mcp-common/src/runs.ts`; do not create another run-id,
  trace-id, or session-id convention.
- The repo quality gates: MCP common changes require vitest coverage in
  `mcp/aptl-mcp-common/tests`, affected server tests such as
  `mcp/mcp-red/tests`, rebuilds for dependent MCPs, and
  `pre-commit run --all-files` before completion.

## Extensibility

The next reasonable change is adding another named composite without editing
the server factory's core dispatch logic. The seam is a typed composite
registration entry with:

- a stable tool name and description;
- a JSON Schema input contract;
- declared context needs (`ssh`, `api`, or both);
- bounded per-step timeout and output-size policy;
- a result formatter that produces a compact, redacted summary while leaving
  raw evidence in the existing capture surfaces.

Do not generalize this into a YAML workflow language, DAG executor, cross-MCP
RPC bus, or agent-planning DSL for ORC-003. If later requirements need those,
they should be designed separately with their own auth, validation,
observability, and non-contamination analysis.

## Non-Goals

- Do not replace `*_run_command`, `*_session_command`, predefined API queries,
  or persistent sessions.
- Do not add a second MCP server framework or per-server startup pattern.
- Do not create a Python-side MCP composite runner for TypeScript MCP tools.
- Do not redesign OTel, OCSF, run archives, Kali capture, Docker Compose, or
  SOC TLS as part of composite tools.
- Do not make composite tools a hidden privilege escalation path from a
  domain-specific tool to host Docker, local filesystem, or blue/SOC APIs.
- Do not promise complete shell AST parsing or perfect semantic interpretation
  of arbitrary tool output.

## Anti-Patterns

- A composite implemented as `child_process.exec("nmap " + target)` on the MCP
  host.
- A generic `run_steps` or `workflow` tool that accepts arbitrary commands,
  URLs, headers, or JSON paths from the agent.
- Duplicate `LabConfig`, API auth, TLS, session, run-id, or error-envelope
  schemas under a composite directory.
- Command output parsing by brittle text snippets when structured output is
  available.
- Hiding internal step commands from red capture or emitting a polished report
  with no underlying evidence surface.
- Combining Kali scan results with Wazuh/Suricata alerts in a red-side tool.
- Logging raw composite args/results to stderr because the top-level tool is
  "only a report."

## References

- ORC-003 / GitHub issue #477 - Composite MCP Tools.
- [ADR-003](adr-003-mcp-common-library.md): MCP Common Library.
- [ADR-004](adr-004-persistent-ssh-sessions.md): Persistent SSH Sessions.
- [ADR-012](adr-012-opentelemetry-integration.md): OpenTelemetry Integration.
- [ADR-027](adr-027-red-team-structured-logging.md): Red Team Structured
  Logging Boundary.
- [ADR-029](adr-029-control-plane-secret-handling.md): Control-Plane Secret
  Handling.
- [ADR-033](adr-033-agent-reasoning-trace-boundary.md): Red-Side Behavioural
  Capture and Non-Contamination Boundary.
- [ADR-034](adr-034-lab-managed-soc-tls-ca.md): Lab-Managed CA for Verified
  SOC Stack TLS.
