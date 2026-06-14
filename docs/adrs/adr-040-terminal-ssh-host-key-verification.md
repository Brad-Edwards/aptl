# ADR-040: Terminal SSH Host-Key Verification Boundary

## Status

accepted

## Date

2026-06-13

## Context

Issue #418 identifies that the operator-facing WebSocket terminal relay opens
its `asyncssh` client connection with `known_hosts=None`. That disables SSH
server host-key verification on the connection that carries the operator's
interactive PTY input.

The relay's attack surface is narrow because the current dial target is
loopback or lab-local, and the route already gates access with a WebSocket
Origin allowlist, a container allowlist, and a lab-running check. The boundary
is still control-plane: if an attacker can impersonate the SSH endpoint the
relay dials, the relay will stream whatever the operator types.

Relevant incumbents already exist:

- `src/aptl/api/routers/terminal.py` owns the WebSocket terminal route,
  Origin check, terminal error envelope, and `asyncssh` connection.
- `src/aptl/core/endpoints.py` and ADR-036 own canonical endpoint metadata and
  runtime SSH reachability decisions; host-published ports must not be
  duplicated in another registry.
- `src/aptl/core/lab.py` owns ordered lab startup, generated-artifact material,
  and bind-mount preflight timing.
- `src/aptl/core/ssh.py` owns the operator client key pair and distribution of
  public keys into target `authorized_keys`.
- `src/aptl/core/deployment/` and ADR-037 own Docker/Compose interaction
  through `DeploymentBackend`.
- ADR-028 owns generated runtime artifact placement and containment under the
  ignored project state tree.
- ADR-029 owns classification, redaction, and serialization boundaries for
  operator/control-plane secrets.

## Decision

The WebSocket terminal relay must verify SSH server identity. It must not use
`known_hosts=None`, `StrictHostKeyChecking=no`, or any equivalent host-key
verification bypass for the interactive operator relay.

Host-key trust material is generated or learned as lab-start-owned runtime
state and persisted for the lab identity. The terminal request path consumes a
known-good `known_hosts` file; it does not create trust material lazily while an
operator session is being opened. A first-run or clean-state bootstrap may use a
TOFU-style capture only inside startup/provisioning, but once a key is pinned,
host-key mismatch is a fail-closed condition for the terminal relay.

Keep SSH materials separate:

- the operator client private key lives under the host user's SSH directory and
  remains owned by `src/aptl/core/ssh.py`;
- target `authorized_keys` continue to be public client-key material mounted
  through the existing `./keys` path;
- server host keys and `known_hosts` pins are server identity material and must
  not be stored in, parsed as, or mounted through the client-key/authorized-key
  contract.

Endpoint identity must come from the canonical endpoint boundary. Do not add a
second terminal-only endpoint schema with container names, users, host ports,
or host-key file names. The implementation may add a small terminal projection
over `ENDPOINT_REGISTRY` plus runtime container inventory, but the registry and
deployment backend remain the source of container/user/reachability facts.

Generated trust artifacts follow ADR-028: place them under an ignored generated
state root such as `.aptl/`, use containment checks before I/O, write
atomically, and fail startup if a mandatory bind-mount source cannot be
materialized. Private server host-key files, if the chosen design persists them
on the host, are operator secrets for filesystem and archive purposes and must
use restrictive permissions. Public `known_hosts` lines are not secrets, but
they still belong to generated state rather than checked-in config.

Terminal connection failures caused by missing pins, host-key mismatch, bad
known-hosts syntax, or SSH authentication errors are reported to the WebSocket
client through the existing narrow terminal error envelope. Logs may name the
container and validation layer, but must not include operator keystrokes,
private key material, or raw secret-bearing exception payloads.

Readiness probes that intentionally trade identity verification for a cheap
"is port 22 accepting key auth" signal are not precedent for the interactive
relay. If those probes are later hardened, they should reuse the same persisted
known-hosts material, but issue #418 is scoped to the operator terminal relay.

## Security Layers

- **WebSocket auth surface:** `terminal_ws` keeps the existing Origin allowlist,
  container allowlist, and lab-running check before dialing SSH.
- **Endpoint identity gate:** reachable host, port, and user data come from the
  canonical endpoint registry/runtime inventory boundary, not from a new local
  map.
- **SSH trust gate:** `asyncssh.connect` receives a concrete persisted
  `known_hosts` path whose entries match the dialed host/port identity. Missing
  or mismatched host keys fail closed.
- **Generated-state containment:** host-key and known-hosts artifacts are
  written only below their owned generated root after path resolution and
  containment checks.
- **Secret classification:** private host keys and the operator client private
  key are control-plane/operator secrets under ADR-029. Public host-key pins are
  not secrets, but they are still generated runtime state.
- **OS/process exposure:** do not pass private key contents, known-hosts
  contents, or trust decisions through shell strings or process argv. Use
  structured Python APIs or `DeploymentBackend` typed methods for any Docker
  interaction.
- **Error envelopes and observability:** WebSocket errors, API responses, logs,
  diagnostics, snapshots, traces, and run archives must not expose private key
  bytes, operator input, or unredacted secret-shaped exception content.

## Extensibility

The extensibility seam is per-SSH-endpoint trust material rooted under one
generated state directory and keyed by the canonical endpoint identity
(`container_name`, SSH user, target host, and target port). Adding another
interactive terminal target should require extending the canonical endpoint
metadata and registering or materializing its host-key trust material, not
editing a second static terminal endpoint map.

If a future deployment provider cannot expose a local file path to
`known_hosts`, adapt the provider/runtime endpoint projection first so the
terminal still receives one verified SSH identity contract. Do not bypass host
verification because a provider is remote or because containers were rebuilt.

## Non-Goals

- Do not redesign SSH client key generation, target `authorized_keys`, or
  lab-user authentication.
- Do not redesign Docker Compose networking, published ports, or the
  deployment backend protocol beyond the endpoint/trust material needed by the
  relay.
- Do not make the endpoint registry a secret store.
- Do not change intentional vulnerable target credentials or lab realism.
- Do not require operators to manage OpenSSH `~/.ssh/known_hosts` manually for
  the web terminal.
- Do not broaden this issue into a full hardening of every test helper,
  inventory fixture, or readiness probe that currently disables host-key
  checking.

## Anti-Patterns

- Replacing `known_hosts=None` with `known_hosts=[]`, `StrictHostKeyChecking=no`,
  `accept_host_key=True`, or another verification bypass.
- Treating `localhost` or Docker bridge IPs as intrinsically trusted.
- Writing host-key pins during the WebSocket request after the operator has
  initiated an interactive session.
- Storing server host keys beside `authorized_keys` without a distinct contract.
- Duplicating SSH endpoint maps across terminal, snapshot, tests, and Compose.
- Parsing `docker-compose.yml` or shelling out directly from the terminal router
  when `DeploymentBackend` or endpoint registry data already owns the fact.
- Surfacing host-key fingerprints, private key paths with sensitive context, raw
  exceptions, or operator input in WebSocket error messages.
