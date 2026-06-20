# ADR-041: Kali Capture Sidecar Ownership Boundary

## Status

accepted

## Date

2026-06-20

## Context

ADR-033 moved red-side behavioural capture out of the SIEM and into
per-run artifacts. The current Kali-side writers still run in the Kali
container:

- `containers/kali/scripts/aptl-wrap-shell.sh` creates per-session
  directories and runs `script(1)` plus `tcpdump`.
- `containers/kali/entrypoint.sh` starts `auditd` and process accounting
  against `/var/log/aptl/captures/_audit` and `_proc-acct`.
- `mcp/aptl-mcp-common/src/captures.ts` harvests the named volume with
  `docker cp` into `.aptl/runs/<run_id>/kali-side/<session_id>/`.

The workload user is `kali` and intentionally has passwordless sudo for
legitimate red-team tooling. That means ordinary Unix ownership inside the
same container is not a sufficient capture-integrity boundary: after
`sudo su -`, the workload can remove or truncate root-owned files under the
same writable mount. Making a helper daemon root-owned inside Kali, or writing
as a dedicated capture user inside the same mount namespace, does not satisfy
the issue #305 acceptance criteria by itself.

## Decision

Use a dedicated capture sidecar service, `aptl-kali-capture`, as the
Kali-side capture writer. The sidecar is part of the `kali` profile, shares
ONLY the Kali container's network namespace (so tcpdump sees Kali's traffic
and the abstract socket is mutually reachable), and mounts the `kali_captures`
volume read-write. It deliberately does NOT share Kali's PID namespace: a
shared PID namespace would let a sudo-root Kali shell traverse
`/proc/<sidecar-pid>/root` into the sidecar's mount namespace and reach the
evidence. auditd and process accounting are kernel-wide and need no PID
sharing to observe Kali's processes.

**The Kali workload container does not mount `kali_captures` at all, not even
read-only.** A read-only mount blocks writes but not reads: a `sudo`-capable
agent can still `cat` a sibling session's `pty/typescript` or pcap on an `ro`
mount, which would leave issue #305's cross-session-disclosure criterion
(added in the issue thread) unmet. The only way to deny *read, list, and
modify* to a sudo-root shell is to keep the capture sink out of the workload
container's mount namespace entirely. The `kali` user, including after
`sudo su -`, therefore has no filesystem path to any capture evidence,
neither its own session's nor any other's.

The host-side harvest runs `docker cp` against the **sidecar**
(`aptl-kali-capture`), not the workload container, since the sidecar is where
the volume is mounted. This is wired through the existing capture-container
configuration path (`capture_container_name` in the MCP lab config; see
`resolveCaptureContainer`), so no second harvester is introduced.

The Kali ForceCommand wrapper remains the single SSH session ingress point, but
it stops writing capture files directly. Its responsibility becomes:

- validate/fallback `APTL_RUN_ID` and `APTL_SESSION_ID` with the canonical
  OBS-003 identifier contract;
- open a local Unix-domain control connection to the capture sidecar;
- notify the sidecar of session start and session exit;
- continue the shell session if the sidecar is unavailable, logging a narrow
  warning rather than rejecting SSH login.

The sidecar owns all paths below `/var/log/aptl/captures`:

- per-session PTY transcript/timing artifacts;
- per-session pcap rotation;
- `_audit/audit.log`;
- `_proc-acct/pacct`.

The sidecar also owns `auditd` and `accton` startup. Move
`AUDIT_CONTROL`, `AUDIT_WRITE`, and `SYS_PACCT` capability requirements from
the Kali workload service to the sidecar wherever Docker permits. Kali keeps
only capabilities required by red-team tooling, such as `NET_RAW` and
`NET_ADMIN`; it must not retain capabilities whose only purpose is starting,
stopping, or reconfiguring the capture subsystems.

## RPC Contract

The sidecar RPC is a small local control protocol, not a file API.

- Transport: Unix-domain socket only. Prefer an abstract socket, or a socket
  path made available to Kali through a read-only mount, so sudo-root in Kali
  cannot unlink or replace the endpoint.
- Authentication/authority: use kernel peer credentials and a per-session
  control connection. Do not use an env-var token, argv token, shared secret,
  or file token that the Kali workload can read after sudo.
- Messages: bounded JSON frames with a version, event type, run id, session id,
  timestamp, and minimal process metadata. If the chosen PTY recorder needs
  byte frames from the wrapper, those frames are append-only data events on
  the same session connection.
- Path derivation: the sidecar derives all filesystem paths from validated
  run/session ids and fixed capture-root constants. RPC messages must never
  carry absolute output paths, relative path fragments, shell commands, chmod
  modes, delete requests, truncate requests, or arbitrary tcpdump arguments.
- Lifecycle: start is idempotent for a session; exit/EOF finalizes the
  per-session capture. A stop/finalize frame is accepted only from the same
  registered peer connection or registered peer pid. Other Kali processes,
  including sudo-root shells, may at most cause an observable denial-of-service;
  they must not gain a write/delete primitive over capture files.

`script(1)` is not magic by itself in a sidecar. The implementation must make
the sidecar the owner of the PTY transcript data path. Running `script(1)` in
the sidecar is acceptable only if it actually owns the wrapped PTY/session
recording. Otherwise, the sidecar should write script-compatible
typescript/timing artifacts from a wrapper-to-sidecar byte stream. Do not leave
`script(1)` writing in the Kali container and call the result protected.

## Security Layers

- **Auth surface:** no host-published port and no remote API. The only new
  control surface is local to the Kali network namespace (the abstract socket).
  It accepts only the bounded capture-control contract above and never exposes
  command execution or filesystem mutation operations.
- **Secret handling:** the RPC carries correlation ids and capture metadata,
  not secrets. Captured PTY, pcap, audit, and pacct content may contain
  secret-shaped target data by design; treat these files as raw evidence with
  restrictive modes. Do not log transcript bytes, pcap payloads, command lines
  with credentials, or raw audit records from the sidecar on failures.
- **Identifier validation:** reuse the canonical OBS-003 id rule already
  mirrored by `src/aptl/core/runstore.py`, `mcp/aptl-mcp-common/src/runs.ts`,
  MCP ingress session checks, and the Bash wrapper: `^[A-Za-z0-9_][A-Za-z0-9._-]*$`
  and no `..`. Do not add a looser sidecar-only schema.
- **Config shape:** the sidecar is part of the existing Compose `kali` profile,
  not a new durable `aptl.json` feature flag. If implementation needs runtime
  knobs for socket name, capture root, enabled capture classes, or pcap
  rotation limits, define them as sidecar environment variables with explicit
  parser/shape checks and safe defaults. Add `AptlConfig` fields only for
  durable first-party user configuration.
- **OS and mount exposure:** the capture volume is mounted read-write only in
  the sidecar and is **not mounted in the Kali workload at all**. The barrier
  is the absence of the sink from Kali's mount namespace, not `0700
  root:root`, `chattr`, setuid helpers, a non-sudo capture user, or an `ro`
  mount (all of which a `sudo`-capable agent reads through or around).
- **Process argv:** do not pass secrets, full command lines, or user-controlled
  tcpdump expressions through shell strings. Prefer argv arrays and fixed
  recorder arguments such as the existing pcap rotation policy.
- **Error envelopes:** writer unavailability is best-effort: wrapper logs and
  continues; MCP close handlers preserve the existing `harvest_warning`
  behavior; startup/readiness surfaces may report degraded capture state using
  the existing health/readiness pattern. Do not introduce a new exception
  hierarchy or make capture startup a hard precondition for opening a shell.
- **Persistence and harvest:** keep the host-side run layout owned by
  `LocalRunStore` and `mcp/aptl-mcp-common/src/runs.ts`. Keep
  `mcp/aptl-mcp-common/src/captures.ts` as the harvest/chmod boundary and
  preserve its no-PATH Docker binary resolution. Harvest runs against the
  sidecar (`aptl-kali-capture`), resolved through the existing
  container-name configuration path: a `capture_container_name` field on the
  MCP lab config that `resolveCaptureContainer` returns in preference to the
  workload `container_name`. No second harvester is introduced; `docker cp`
  reads the same volume from whichever container mounts it.

## Maintainability

Implementations must build on the existing incumbents:

- `containers/kali/scripts/aptl-wrap-shell.sh`: the single ForceCommand entry
  point and the existing Bash id fallback contract.
- `containers/kali/audit/aptl.rules`: the canonical audit rule set. Copy or
  mount this into the sidecar; do not duplicate rule text.
- `mcp/aptl-mcp-common/src/ssh.ts`: `APTL_SESSION_ID`, `APTL_RUN_ID`, bound
  run id, remote-close await, and best-effort PTY tee semantics.
- `mcp/aptl-mcp-common/src/tools/handlers.ts`: close-session and close-all
  harvest warning envelopes.
- `mcp/aptl-mcp-common/src/captures.ts`: docker-copy harvest, global
  `_audit` / `_proc-acct` collection, destination chmod repair, and
  fail-loud missing-source behavior.
- `src/aptl/core/runstore.py` and `mcp/aptl-mcp-common/src/runs.ts`: per-run
  directory and id contracts.
- ADR-033 non-contamination: do not reintroduce Wazuh, rsyslog, SIEM dispatch,
  or a blue-visible red telemetry feed from Kali.
- ADR-028, ADR-029, ADR-030, ADR-031, and ADR-037 for generated state,
  secret handling, degraded readiness, lifecycle envelopes, and Docker/Compose
  boundary discipline.

Static and live tests should pin the boundary, not just the happy path:

- Compose consistency: `kali_captures` is NOT mounted in the Kali workload at
  all, read-write in `aptl-kali-capture`; sidecar shares Kali pid/net
  namespaces; sidecar has no host ports and no `hostname` (which conflicts
  with `network_mode: service:`); capture-only caps are not on the Kali
  workload service.
- OBS-003 live tests: `sudo su -` in Kali cannot read, list, remove,
  truncate, or modify the capture sink (the volume is absent from Kali's mount
  namespace); per-session PTY, pcap, auditd, and pacct survive a
  `sudo rm -rf /var/log/aptl/captures/*` attempt; a Kali shell in session N
  cannot read session M's captures.
- RPC unit tests: invalid ids, path-bearing messages, delete/truncate frames,
  spoofed stop/finalize attempts, and writer-unavailable paths.
- Existing MCP tests: harvest remains best-effort and surfaces warnings rather
  than breaking command/session results.

## Extensibility

The extensibility seam is the sidecar-owned capture writer contract:

- socket endpoint;
- capture root;
- enabled capture classes;
- pcap rotation limits;
- future session-scoped capture subdirectories under
  `<state>/runs/<run_id>/kali-side/<session_id>/`.

Add the next capture source by extending the sidecar writer and adding a new
subdirectory under the existing per-session or `_global` layout. Do not change
the run archive root, duplicate the harvester, or add another MCP session id
concept.

## PTY transcript authenticity (residual)

This boundary makes capture evidence **undeletable and unreadable** by the
Kali workload, and makes the genuinely Kali-side witnesses (per-session
**pcap**, **auditd**, and **process accounting**) **tamper-resistant**,
because the sidecar produces them from kernel sources the workload does not
feed. It does **not** make the Kali-side PTY *typescript* tamper-proof for the
workload's own session.

The reason is fundamental: a shell transcript is generated by the shell, which
runs in the Kali container. Any capture of it that the workload can feed or
write (here, `script(1)` to a wrapper FIFO to `aptl-capture-client` to the
sidecar RPC) can be forged by a sudo-capable workload for its own session: it
can type fake output, run the client by hand, or write to the FIFO/fds of its
own wrapper. Connection ownership stops one session from forging *another*
session's transcript and the single-use session-id rule stops reopening a
*finalized* session for append, but neither prevents a session from forging
*its own* in-flight transcript.

The authoritative, tamper-resistant keystroke/output record is therefore the
**MCP-side PTY tee** (`createPtyTeeWriter` in `mcp/aptl-mcp-common/src/runs.ts`),
which runs in the MCP server process outside every container and which the Kali
workload cannot reach, exactly as issue #305's own framing states. The
Kali-side typescript is a convenience secondary to it.

Fully tamper-proofing the Kali-side typescript would require the sidecar to own
the PTY master itself (moving sshd / PTY proxying into the sidecar), a much
larger rearchitecture that changes the SSH/shell execution model and is out of
scope for this boundary. It would be its own ADR if pursued.

## Consequences

### Positive

- The capture sink is outside the Kali workload's write authority, including
  sudo-root inside the Kali container.
- The red workload remains operational when the writer is degraded.
- The architecture preserves ADR-033 non-contamination by keeping observation
  outside the blue defensive stack.
- MCP-side PTY tee, tool-call JSONL, OCSF JSONL, and Kali-side artifacts keep
  the same correlation keys and host-side run layout.

### Negative

- The lab gains another container in the `kali` profile.
- Session capture now has an RPC lifecycle that must be tested for ordering,
  spoofing, and unavailable-writer behavior.
- PTY transcript capture needs deliberate design; sharing the network
  namespace alone does not make sidecar `script(1)` observe a shell. The
  Kali-side transcript is therefore supplied by the workload over the RPC and
  is NOT tamper-resistant against a sudo-capable Kali user (see "PTY transcript
  authenticity" below); the authoritative keystroke/output record is the
  MCP-side PTY tee, and the tamper-resistant Kali-side witnesses are the
  sidecar-produced pcap, auditd, and process-accounting streams.

### Risks

- A sudo-root Kali workload can still attempt denial-of-service against the
  session, wrapper, network namespace, or capture sidecar. This ADR prevents
  read, delete, alter, and truncate of capture evidence from Kali; it does
  not make the workload incapable of noisy self-sabotage.
- Docker/runtime differences around auditd, process accounting, and Unix
  socket mounts can degrade capture on some hosts. That degradation must be
  visible through the existing readiness/logging surfaces.
- If implementation mounts the volume in Kali at all (even read-only), the
  design fails the cross-session read-isolation acceptance criterion regardless
  of daemon code quality: `ro` blocks writes, not a sudo-root `cat`.

## Non-Goals

- Do not remove Kali passwordless sudo or reduce legitimate red-team tooling.
- Do not redesign MCP command execution, session queues, OCSF schemas,
  redaction helpers, runstore layout, or export/archive semantics.
- Do not make capture writer availability a hard gate for SSH login.
- Do not add a database, broker, remote service, or SIEM transport for the
  capture path.
- Do not solve complete anti-evasion or anti-DoS against a sudo-capable
  workload in this issue.

## Anti-Patterns

- Treating root-owned files, setuid helpers, ACLs, or a dedicated capture user
  inside the same writable Kali container as tamper-resistant against
  `sudo su -`.
- Mounting `kali_captures` into Kali at all (read-write or read-only) for
  wrapper or harvest compatibility. A read-only mount still exposes every
  session's evidence to a sudo-root `cat`.
- Letting the wrapper create, chmod, truncate, rotate, or delete files under
  `/var/log/aptl/captures`.
- Adding a second id regex, second run directory layout, second harvester, or
  second capture-warning envelope.
- Accepting arbitrary paths, shell commands, tcpdump filters, delete requests,
  or chmod/chown requests over the sidecar RPC.
- Authenticating the RPC with a token in environment variables, argv, a file in
  Kali, or any material readable by the workload after sudo.
- Reintroducing any red-to-SIEM pipe as a shortcut for durable capture.

## Related

- [Issue #305](https://github.com/Brad-Edwards/aptl/issues/305)
- [ADR-033: Red-Side Behavioural Capture and Non-Contamination Boundary](adr-033-agent-reasoning-trace-boundary.md)
- [ADR-029: Control-Plane Secret Handling in Run Data and Local State](adr-029-control-plane-secret-handling.md)
- [ADR-037: Docker Compose Backend Cohesion](adr-037-docker-compose-backend-cohesion.md)
