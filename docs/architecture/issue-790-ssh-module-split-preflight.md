# Issue 790 SSH Module Split Preflight

This note fixes the architecture guardrails for the quality-budget refactor. It
is design guidance, not an implementation plan. ADR-003, ADR-004, ADR-033, and
ADR-042 remain authoritative for the common-library API, session lifecycle,
capture correlation, and PTY ownership boundaries.

## Architecture Decisions

- Keep `mcp/aptl-mcp-common/src/ssh.ts` as the compatibility facade for the
  existing SSH exports. Root-package consumers and internal imports through
  `ssh.js` must continue to receive the same class and type contracts, and
  `src/index.ts` must keep its current root-package export surface. Do not
  introduce a second class definition or wrapper class merely to preserve a
  path.
- Give `PersistentSession` and `SSHConnectionManager` separate implementation
  modules. `PersistentSession` owns shell-channel state, queueing, parsing,
  buffering, PTY teeing, timers, local cleanup, and the awaitable remote-close
  latch. `SSHConnectionManager` owns SSH clients, connection and session maps,
  in-flight creation joins, public lookup/orchestration, and the two-phase
  session-before-transport shutdown sweep.
- A focused internal SSH contracts leaf may hold only cross-class contracts:
  the existing public SSH types and `SSHError`, common contract assertions and
  defaults, command-error redaction, and correlation-environment construction.
  Session-only buffer/timer policy stays with `PersistentSession`;
  connection-only client policy and teardown bookkeeping stay with the manager.
  Do not create a generic common/utils layer.
- Dependency direction must remain acyclic: the facade re-exports; the manager
  depends on the session implementation and shared contracts; the session
  depends on shared contracts plus the existing shell, run-capture, and
  redaction modules. Shared contracts must not import either class.
- Every TypeScript source file in the split must stay comfortably below the
  500 non-comment-line budget. Do not meet S104 by suppressing the rule,
  excluding files from Sonar, compressing code, deleting useful comments, or
  moving behavior into tests/generated output.

## Preserved Runtime Contracts

- Local close cleanup remains synchronous: mark inactive, clear every timer,
  reject the in-flight request, and reject all queued requests exactly once.
- `close()` and manager-level close operations remain awaitable until remote
  channel close or the existing bounded warning path. A `closed` event cannot
  release a session ID before cleanup is verified and that await settles.
- `disconnectAll()` continues to quiesce pending session/connection creations,
  close all sessions before parent transports, attempt the whole sweep despite
  individual failures, clear both maps, and surface aggregate failure through
  `SSHError`.
- Normal/raw mode inheritance, background immediate-return behavior, delimiter
  parsing, command result shape, constructor defaults and parameter order,
  copied session metadata, timeout text, and event names/timing are behavioral
  compatibility requirements, not refactor opportunities.
- `aptlShellEnv` semantics remain one policy for one-shot and persistent paths:
  `APTL_SESSION_ID` plus the open-time `APTL_RUN_ID`/`APTL_TRACE_ID`. The bound
  run ID continues to drive close-time harvest after scenario rotation.

## Cross-Cutting Layers and Canonical Incumbents

| Layer | Existing owner and required behavior |
|---|---|
| MCP ingress and auth | `src/server.ts` uses local `StdioServerTransport`; this refactor adds no network listener, token, or authorization surface. `src/tools/definitions.ts` owns the `session_id` JSON Schema; `src/tools/handlers.ts` owns the no-`..` assertion and argument-to-session orchestration. The split adds no DTO, parser, or validation path. |
| Configuration | `src/config.ts` owns `LabConfig`, JSON parsing and required-section/capability/config-key checks, environment substitution, SSH-key tilde expansion, `getTargetCredentials`, port/user/target lookup, and shell selection. There is no separate SSH Zod schema to reproduce. No config or environment shape changes. |
| Authentication and secrets | `SSHConnectionManager` continues to read the configured private-key file into memory and pass it directly to `ssh2`. Key contents and credentials must never enter process argv or logs, and commands must not be launched through a local shell or process argv. Command-bearing timeout errors continue through the canonical `redact()` policy. |
| SSH and shell policy | `ssh2` remains the sole transport and `src/shells.ts` remains the shell-format strategy. Preserve the existing `shellType` parameter from config through manager construction to `createShellFormatter`; do not duplicate delimiter or shell quoting logic. |
| Correlation and persistence | `src/runs.ts` remains the owner of active trace lookup, run paths, ID checks, and `createPtyTeeWriter`; `src/captures.ts` remains the only Docker-copy harvester. In-memory connection/session/pending maps remain manager state—no repository or durable session store is introduced. |
| Errors and envelopes | `SSHError` remains the only SSH exception type. `src/tools/handlers.ts` continues to normalize errors into existing MCP result envelopes and `harvest_warning`; `src/server.ts` continues to route calls through `traceToolCall` and best-effort post-tool hooks. Do not expose causes, key material, or unredacted command text. |
| Logging and shutdown | Keep protocol output on MCP stdio and diagnostics on stderr using the existing `[SSH]`, `[SSH-CLIENT]`, and `[MCP]` paths. `src/server.ts` remains the SIGINT/SIGTERM owner and calls `disconnectAll()`; class extraction must not register process handlers. |
| Host/runtime capture | `APTL_*` travels via SSH `env`, not argv. Kali/sidecar `AcceptEnv` and ID validation remain outside this refactor. No new child process is needed; the existing Docker harvester passes validated IDs and paths as argument-array elements. Remote close must still precede `src/tools/handlers.ts` harvest orchestration so capture flush is not raced. |
| Quality workflow | `sonar-project.properties`, `.gc/plan-rules.md`, `.pre-commit-config.yaml`, `.github/workflows/checks.yml`, `mcp/build-all-mcps.sh`, and each dependent package's `file:../aptl-mcp-common` dependency are the canonical analysis/build/test path. Fresh common build artifacts must be reinstalled before dependent verification; do not add a Sonar exclusion. |

## Extensibility Seam

The class-module boundary is the seam for the next lifecycle change: shell
behavior changes belong in `PersistentSession`; pool/transport behavior changes
belong in `SSHConnectionManager`; neither requires editing the public facade.
Keep shell variation parameterized by the existing `shellType`/
`ShellFormatter` strategy. Keep the remote-close threshold as internal timeout
policy, as ADR-004 requires; this refactor does not promote it to an MCP argument
or durable configuration field.

## Gotchas and Anti-Patterns

- Do not split a single lifecycle across callbacks in both class modules. The
  manager observes session events; it does not mutate session internals.
- Do not duplicate public interfaces, timeout constants, ID rules, redaction,
  correlation env construction, `SSHError`, teardown result shapes, or error
  envelopes to avoid an import.
- Preserve listener installation before `initialize()` awaits, the pending-ID
  reservation before any await, and once-only cleanup/event latches. Reordering
  these creates startup, duplicate-ID, stranded-promise, or double-close races.
- Preserve ESM `.js` specifiers and declaration generation. Do not add package
  subpath exports: the package root and `src/ssh.js` compatibility path are the
  contracts under test.
- Do not relocate harvest into either SSH class, await best-effort PTY writer
  I/O on the command-response path, or tear down parent clients while sessions
  are still awaiting remote close.
- Do not use a barrel that causes runtime cycles or creates two `SSHError` or
  class identities. Type-only imports should be type-only where applicable.

## Non-Goals and Boundaries

This issue does not redesign SSH behavior, public exports, tool schemas, config,
authentication, shell formatting, logging, telemetry, capture storage/harvest,
timeouts, session persistence, or process shutdown. It does not add a generic
transport interface, dependency-injection framework, repository layer, new
exception hierarchy, Sonar exemption, package subpath API, or unrelated cleanup
of other over-budget source files.
