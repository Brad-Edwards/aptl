# ADR-004: Persistent SSH Session Architecture with Command Queuing

## Status

accepted

## Date

2025-08-30

## Context

AI agents interact with lab containers by sending commands through MCP tool calls. Each tool call translates to an SSH command on the target container. The naive approach — open SSH connection, run command, close connection — has serious problems when an AI agent is the client:

### Problems with Per-Command SSH

1. **Latency**: SSH handshake + authentication + channel setup takes 200-500ms per command. AI agents issue rapid sequences of commands (nmap, then cat a result file, then grep, then curl). The overhead dominates execution time.

2. **State loss**: Each new SSH connection starts a fresh shell. Environment variables, working directory, shell history, and background processes are lost between commands. An agent that `cd /tmp && wget exploit.sh` in one command finds itself back in `~` on the next.

3. **Resource churn**: Rapid connect/disconnect cycles stress the SSH daemon on containers and exhaust file descriptors on the MCP server host.

4. **MCP is stateless, SSH is stateful**: The MCP protocol is request-response with no session concept. But SSH sessions are inherently stateful — they maintain a shell process, environment, and working directory. Bridging these paradigms requires an explicit session layer.

### AI Agent Behavior Patterns

Observations from early agent testing revealed:

- Agents issue 5-20 commands in rapid succession during reconnaissance phases
- Agents frequently set up working environments (`export`, `cd`, `alias`) and expect them to persist
- Agents run long-running commands (nmap full-port scans, compilation) alongside quick checks
- Agents sometimes abandon sessions mid-task when switching strategies

## Decision

Implement a **`PersistentSession`** class in `mcp/aptl-mcp-common/src/ssh.ts` that provides long-lived, stateful SSH sessions with command queuing.

### Architecture

```
AI Agent → MCP Tool Call → SSHConnectionManager → PersistentSession → SSH Channel → Container Shell
                                    ↓
                           Session Pool (by connection key)
                           - session-1: kali interactive
                           - session-2: kali background
                           - session-3: victim interactive
```

### Key Design Elements

**Long-lived shell channels**: A `PersistentSession` opens a single SSH shell channel on construction and keeps it open for the session lifetime (default: 10 minutes, configurable). All commands execute in the same shell process, preserving state.

**Delimiter-based output parsing**: Since multiple commands share one shell stream, output boundaries are ambiguous. Each command is wrapped with unique delimiters:

```bash
echo '<<<DELIM_abc123_START>>>'
<actual command>
echo '<<<DELIM_abc123_END_$?>>>'
```

The session parser watches the output stream for these delimiters and extracts the command's stdout, stderr, and exit code. The delimiter includes a unique ID to prevent collisions with command output.

**FIFO command queue**: Commands are queued and executed sequentially within a session. When command A is running, command B waits in the queue. This prevents output interleaving while allowing the agent to pipeline commands.

**Per-command timeouts**: Each command has an individual timeout (default: 30 seconds, configurable per call). Long-running commands like nmap scans can specify longer timeouts. The session itself has a separate inactivity timeout.

**Buffer overflow protection**: Output buffers are capped at 10,000 lines. When exceeded, the buffer is trimmed to the most recent 5,000 lines. This prevents memory exhaustion from verbose commands (e.g., `find /` or chatty compilation output).

**Keepalive**: SSH keepalive packets every 30 seconds prevent connection drops from inactive sessions. Max 3 missed keepalives before declaring the connection dead.

**Shell formatter strategy pattern**: The `ShellFormatter` interface abstracts shell-specific command formatting. Implementations exist for bash, sh, PowerShell, and cmd. Each formatter knows how to:
- Set environment variables (`export FOO=bar` vs `$env:FOO='bar'` vs `set FOO=bar`)
- Change working directory
- Format the delimiter-wrapped command envelope

This supports the reverse engineering container (Ubuntu/bash) and future Windows containers (PowerShell/cmd) with the same session infrastructure.

**Session types**: `interactive` (default) for command-response workflows, `background` for long-running tasks. Background sessions don't block the command queue.

**Immutable metadata**: Session metadata (ID, target, creation time, history) is exposed as a copy to prevent callers from mutating internal state.

### Connection Manager

`SSHConnectionManager` maintains a pool of `PersistentSession` instances keyed by `{target}-{sessionId}`. It handles:

- Session creation with SSH key authentication
- Session lookup and listing
- Graceful cleanup: pending command promises are rejected on close (fixed in v4.6.7 after a bug where cleanup left callers stranded)
- Connection error recovery

## Consequences

### Positive

- **State preservation**: Agent workflows that span multiple commands (reconnaissance, exploitation, post-exploitation) work naturally
- **Performance**: Single SSH handshake amortized across dozens of commands. Order of magnitude latency reduction.
- **Concurrent sessions**: An agent can maintain separate sessions for different tasks on the same container
- **Shell-agnostic**: Strategy pattern supports multiple shell types without changing the session infrastructure

### Negative

- **Complexity**: Delimiter-based parsing is inherently fragile. Commands that output text matching the delimiter pattern could confuse the parser (mitigated by unique IDs).
- **Resource retention**: Long-lived sessions hold SSH connections and shell processes open. Must rely on timeouts and explicit cleanup.
- **Queue head-of-line blocking**: A slow command (long nmap scan) blocks subsequent commands in the same session. Agents must create separate sessions for parallel work.

### Risks

- Session timeout tuning: Too short drops sessions mid-task; too long wastes resources. The 10-minute default was chosen based on observed agent interaction patterns but may need adjustment.
- Buffer trimming can lose important early output from long-running commands. The 10,000/5,000 line limits were set based on typical command output sizes.
- The v4.6.7 stranded-callers bug showed that cleanup paths must be exhaustively tested — any code path that closes a session must reject all pending promises.

## Update (2026-05-12): Contract hardening guardrails

Issue #215 asks for SSH session usage and cleanup contracts. The runtime
session contract lives in `mcp/aptl-mcp-common/src/ssh.ts`, not in
`src/aptl/core/ssh.py`, which only owns local lab key generation and public-key
distribution. Contract hardening for command execution must therefore protect
`PersistentSession.executeCommand()`, `PersistentSession.close()/cleanup()`,
and `SSHConnectionManager.executeInSession()/closeSession()/disconnectAll()`.
Do not add a parallel Python session manager or treat key generation contracts
as satisfying the persistent-session cleanup guarantee.

The invariant to preserve is:

- Commands may be accepted only while the target session is initialized,
  has an open shell, and is active in the manager's session map.
- Every session close path, timeout path, shell close event, manager removal,
  and process shutdown must leave the session inactive, clear keepalive/session
  and per-command timers, reject the in-flight command, and reject every queued
  command exactly once.
- Contract failures must use the existing `SSHError`/MCP error response path
  and remain safe for `traceToolCall()`/redaction. They must not introduce a
  second exception hierarchy, second tool response envelope, or raw secret
  logging path.
- The MCP JSON Schema tool definitions and `LabConfig`/`getTargetCredentials`
  remain the input/config validation boundary. Do not duplicate those shapes in
  ad hoc validators.
- Changes under `mcp/aptl-mcp-common` must extend the existing vitest SSH
  coverage and rebuild dependent MCP packages, because all SSH-based MCP
  servers consume the same session implementation.

If a future Python SSH session layer is introduced, it must first be designed
as a distinct control-plane boundary. The existing `src/aptl/core/ssh.py`
module should remain limited to key material lifecycle unless a separate ADR
expands its ownership.
