# ADR-042: Sidecar-Owned PTY Master for Kali Transcript Authenticity

## Status

accepted

## Date

2026-06-20

## Context

ADR-033 made the MCP-side PTY tee the authoritative record of red-side
keystrokes and output, and moved red-side evidence out of the blue SIEM.
ADR-041, from issue #305, moved Kali-side capture writes into the
`aptl-kali-capture` sidecar so the Kali workload cannot read, list, delete, or
modify captured evidence. That sidecar boundary protects the capture volume and
the genuinely Kali-side witnesses the workload does not feed directly: pcap,
auditd, and process accounting.

ADR-041 deliberately left one residual. The Kali-side PTY `typescript` is still
fed by the workload session path: `script(1)` in the Kali wrapper writes to a
FIFO, `aptl-capture-client` forwards those bytes, and the sidecar persists
them. Connection ownership prevents one session from appending to another
session, and single-use session IDs prevent reopening a finalized session, but
the in-flight session can still forge its own transcript by writing to its
wrapper/FIFO/client path or by generating fake transcript bytes before the
sidecar sees them.

ADR-041's "PTY transcript authenticity (residual)" section deferred closing
this gap to a future ADR that moves PTY-master ownership into the sidecar. This
ADR is that follow-up and supersedes that residual.

The acceptance criterion for issue #516 is stronger: a sudo-capable Kali
workload must not be able to forge or omit its own Kali-side recorded PTY
transcript without detection, while interactive red-team tooling keeps PTY
semantics, exit-code propagation, and environment passthrough.

## Decision

The Kali-side PTY transcript must be produced from a PTY master that is owned
outside the Kali workload authority. The `aptl-kali-capture` sidecar, or a
sidecar-fronted PTY broker with equivalent isolation, owns:

- the PTY master;
- the raw input and output recording stream;
- transcript/timing/integrity metadata writes under `kali_captures`;
- the session lifecycle event that finalizes the transcript.

The Kali workload may receive only the PTY slave attached as the shell's
controlling terminal. Bytes written by the workload to the slave are then real
terminal output and are recorded by the sidecar-owned master; the workload must
not hold a writable handle to the transcript file, the sidecar recording
stream, or a workload-fed FIFO/client path that is treated as authentic
transcript input.

The user-facing execution model remains the existing MCP SSH session model.
`mcp/aptl-mcp-common/src/ssh.ts` continues to own `PersistentSession`, command
queueing, raw/normal mode semantics, delimiter handling, remote-close
awaiting, `APTL_SESSION_ID` / `APTL_RUN_ID` / `APTL_TRACE_ID` propagation, and
the MCP-side `createPtyTeeWriter` cross-check. The implementation may move the
SSH endpoint into the sidecar or place an SSH-compatible PTY proxy in front of
the Kali shell, but the boundary that allocates the PTY master and records the
transcript must be outside the Kali workload container.

`script(1)` remains acceptable only as an output compatibility format or as a
tool running in the sidecar-owned PTY path. Running `script(1)` in the Kali
workload, then forwarding its log to the sidecar, does not satisfy this ADR.

The sidecar-produced transcript should preserve the existing
`pty/typescript` and `pty/timing` artifact contract where practical. If
detection metadata is needed, it belongs beside those artifacts under the same
sidecar-owned per-session directory, for example sequence numbers, byte counts,
directions, close reason, and a running hash. Do not move this into a new run
archive root or a second harvest path.

## Attacker Model

The attacker is the normal Kali workload user with passwordless sudo inside the
Kali workload container. The design must assume the attacker can become root in
that container, inspect its processes and file descriptors, write to the PTY
slave, kill its own shell, emit terminal escape sequences, and attempt denial
of service.

The attacker must not be able to:

- access the `kali_captures` volume from the Kali workload mount namespace;
- access sidecar process file descriptors through a shared PID namespace;
- write transcript bytes through any path other than the actual PTY slave;
- truncate, replace, or append to sidecar-owned transcript artifacts;
- finalize another connection's session or reopen a finalized session ID;
- hide transcript gaps without a sidecar-visible close, error, or integrity
  anomaly.

This ADR does not claim that terminal output is truthful. A shell can always
print misleading text. The claim is narrower and testable: the recorded
Kali-side transcript is the byte stream observed at the sidecar-owned PTY
master, plus sidecar-owned lifecycle metadata, not a workload-supplied log.

## Security Layers

- **MCP auth and input surface:** keep the existing MCP JSON Schema tool
  definitions and handler assertions as the ingress boundary for `session_id`
  and command arguments. Do not add sidecar-specific MCP session ID shapes or
  tool envelopes.
- **SSH/session boundary:** keep `PersistentSession` as the command lifecycle
  owner. The sidecar endpoint/proxy must preserve normal mode delimiters, raw
  mode behavior, background sessions, window/signal behavior, remote-close
  semantics, and exit-code propagation visible to `ssh.ts`.
- **Correlation environment:** preserve `APTL_SESSION_ID`, `APTL_RUN_ID`, and
  `APTL_TRACE_ID` from `aptlShellEnv`. The sidecar or proxy may validate and
  forward those values, but must not invent a second correlation vocabulary.
- **Identifier validation:** reuse the canonical OBS-003 ID rule already
  mirrored in `src/aptl/core/runstore.py`, `mcp/aptl-mcp-common/src/runs.ts`,
  MCP handler checks, and ADR-041 sidecar code: `^[A-Za-z0-9_][A-Za-z0-9._-]*$`
  and no `..`.
- **Config shape:** keep durable user config out of `aptl.json` unless
  `AptlConfig` gets a real field and consumer per ADR-025. Sidecar runtime
  knobs such as socket name, PTY launch adapter, capture root, enabled capture
  classes, or pcap rotation limits belong in sidecar environment variables
  with explicit parser/shape checks and safe defaults.
- **Secret handling:** ADR-029 remains canonical. Transcript, pcap, audit, and
  pacct files are raw evidence and may contain target secrets by design; logs,
  MCP responses, OTel attributes, readiness diagnostics, and error messages
  must not echo transcript bytes, command lines with credentials, private keys,
  tokens, cookies, or raw audit records.
- **OS and mount exposure:** `kali_captures` stays mounted read-write only in
  the sidecar and not mounted in Kali, even read-only. Do not share the
  sidecar PID namespace with Kali. Do not mount the Docker socket into a
  network-reachable sidecar as a shortcut for spawning shells unless a later
  ADR explicitly accepts that host-root control-plane exposure.
- **Process argv:** do not pass secrets, command lines, transcript bytes, or
  user-controlled tcpdump expressions through shell strings or process argv.
  Use fixed recorder arguments and structured APIs.
- **Persistence and harvest:** keep `LocalRunStore`,
  `mcp/aptl-mcp-common/src/runs.ts`, and
  `mcp/aptl-mcp-common/src/captures.ts` as the run-layout and harvest
  boundaries. Harvest still targets the configured `capture_container_name`
  and preserves chmod repair, global `_audit` / `_proc-acct` collection, and
  fail-loud missing-source behavior.
- **Error envelopes and observability:** preserve existing `SSHError`, MCP
  JSON result envelopes, `harvest_warning`, stderr logging style, and degraded
  readiness patterns. Do not introduce a second exception hierarchy or make
  capture startup a new hard precondition for SSH login unless the user-facing
  behavior is explicitly redesigned.

## Maintainability

Implementations must build on the existing incumbents rather than parallel
systems:

- `mcp/aptl-mcp-common/src/ssh.ts`: `PersistentSession`,
  `SSHConnectionManager`, `SessionMode`, command queueing, close semantics,
  and `aptlShellEnv`.
- `mcp/aptl-mcp-common/src/runs.ts` and
  `src/aptl/core/runstore.py`: run/session path construction and ID
  validation.
- `mcp/aptl-mcp-common/src/captures.ts` and
  `mcp/aptl-mcp-common/src/tools/handlers.ts`: best-effort harvest and
  `harvest_warning` projection.
- ADR-041 sidecar writer boundary: capture volume ownership, no Kali mount,
  no PID sharing, bounded local control surface, and sidecar ownership of
  pcap/auditd/pacct.
- ADR-033 non-contamination: no Wazuh agent, rsyslog path, SIEM forwarding, or
  blue-visible red telemetry feed from Kali.
- ADR-025, ADR-028, ADR-029, ADR-030, ADR-031, and ADR-037 for config schema,
  generated state, secret handling, readiness classification, contract
  envelopes, and Docker/Compose boundary discipline.

Keep the evidence concepts separate:

- MCP-side PTY tee: external, authoritative cross-check outside every
  container.
- Kali-side PTY transcript: sidecar-owned raw terminal stream and lifecycle
  metadata.
- Kernel witnesses: sidecar-produced pcap, auditd, and process accounting.

Do not collapse these into one "session transcript" schema or treat one layer's
presence as proof that another layer is authentic.

## Extensibility

The seam belongs at the sidecar's session-launch adapter and recorder
configuration, not in MCP tool arguments. The next reasonable variation is a
different way to attach the sidecar-owned PTY slave to a workload process, or
the same PTY-master ownership pattern for another SSH-controlled workload.
That should require adding or swapping a sidecar-internal adapter, not editing
the run archive layout, creating another session ID vocabulary, or duplicating
MCP session management.

Parameterize only the parts that are real variation points:

- PTY launch adapter;
- socket or local endpoint name;
- capture root;
- enabled capture classes;
- pcap rotation limits;
- transcript metadata format version.

## Verification Guardrails

Tests should prove the ownership boundary, not only artifact creation:

- static Compose tests: Kali does not mount `kali_captures`; sidecar owns the
  volume; sidecar does not share Kali PID namespace; capture-only capabilities
  stay off the Kali workload service; no host ports expose the capture control
  surface.
- MCP/common tests: `capture_container_name` remains the harvest target;
  close-session and close-all warnings keep the existing envelopes; invalid
  IDs fail at ingress.
- sidecar unit tests: invalid IDs, path-bearing frames, delete/truncate/chmod
  requests, duplicate/finalized session IDs, spoofed finalize attempts,
  dropped connections, and transcript integrity metadata.
- live OBS-003 tests: a `sudo su -` Kali shell cannot read, list, delete,
  modify, append to, or directly feed its own sidecar transcript; killing the
  wrapper or shell produces a visible close/degraded/integrity signal; PTY
  behavior, raw interactive tooling, non-echoed input recording, env
  passthrough, and exit-code propagation still work.

Changes under `mcp/aptl-mcp-common` still require rebuilding and testing every
dependent MCP package per the repo plan rules.

## Non-Goals

- Do not remove Kali passwordless sudo or reduce legitimate red-team tooling.
- Do not redesign MCP commands, session queues, raw/normal mode semantics,
  OCSF schemas, redaction helpers, runstore layout, exports, or collectors.
- Do not replace the MCP-side PTY tee; keep it as the independent
  tamper-resistant cross-check.
- Do not make the sidecar transcript a blue-SIEM signal.
- Do not solve complete anti-evasion or anti-DoS against a sudo-capable
  workload.
- Do not add a database, queue, remote service, or generic command-execution
  broker for this issue.

## Anti-Patterns

- Treating workload-fed `script(1)` output, wrapper FIFOs, or
  `aptl-capture-client` byte frames as authentic Kali-side transcript input.
- Moving `script(1)` into a helper process while the Kali workload still owns
  the PTY master or transcript feed.
- Mounting `kali_captures` into Kali, even read-only.
- Sharing the sidecar PID namespace with Kali.
- Adding a second ID regex, session DTO, transcript schema, harvester, or
  error envelope.
- Passing transcript bytes, secrets, commands, tcpdump filters, file paths, or
  chmod/delete requests through the sidecar control protocol.
- Authenticating sidecar control with tokens in env vars, argv, files, or
  other material readable by the Kali workload after sudo.
- Bypassing `PersistentSession` with a bespoke MCP-side SSH client to make the
  PTY proxy easier.
- Mounting the Docker socket into the capture sidecar without a separate
  accepted design for that host-root exposure.

## Related

- Issue #516
- Supersedes the "PTY transcript authenticity (residual)" section of [ADR-041: Kali Capture Sidecar Ownership Boundary](adr-041-kali-capture-sidecar-ownership-boundary.md)
- [ADR-033: Red-Side Behavioural Capture and Non-Contamination Boundary](adr-033-agent-reasoning-trace-boundary.md)
- [ADR-029: Control-Plane Secret Handling in Run Data and Local State](adr-029-control-plane-secret-handling.md)
- [ADR-037: Docker Compose Backend Cohesion](adr-037-docker-compose-backend-cohesion.md)
