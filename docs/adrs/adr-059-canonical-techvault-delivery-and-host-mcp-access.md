# ADR-059: Canonical TechVault Delivery and Host MCP Access

## Status

accepted

Implemented by issue #868. Software integration verification is distinct
from signed appliance qualification and offline VM boot evidence.
This partially supersedes ADR-049's guest-agent-only access
policy and developer-only restriction on ordinary local use. ADR-000 keeps
the accepted historical record immutable. All other ADR-049 containment,
capture, signing, and qualification requirements remain binding.

## Date

2026-09-17

## Context

Issue #868 makes the packaged full TechVault deployment the shared input to
normal local use, the participant workbench, and optional appliance delivery.
It must merge before #1022 builds and qualifies real seats. There is no Ground
Control requirement; the issue is the acceptance contract.

Before this change, the contracts could not satisfy this by changing a scenario name:

- `core/scenario_bundle.py` resolves the packaged `raes_env_packs` TechVault
  bundle and validates its content identity. Participant `ScenarioReference`
  and `_validate_profile_links()` instead require a project catalog path.
- `workbench/profiles.py` already defines red, guided-blue, and full blue tool
  inventories. `ParticipantAuthorizer` returns only a boolean; it does not
  bind a caller to an allowed role. Client tool flags are not authorization.
- `workbench/codex_agent.py` is a decision-only adapter. Exercising it does not
  demonstrate Codex calling MCP tools from the host.
- `appliance/offline.py` checks outer filenames, nonempty archives, and an
  APTL wheel version. Those checks do not establish dependency closure, built
  asset integrity, or offline boot capability.
- `GuestPublication` requires loopback, and boundary inventory compares its
  port directly with the outer listener. That conflates two network namespaces.
- Release preparation and verification require a golden disk, signed
  qualification, and two machine drills. Software input validation cannot
  impersonate those results to remove the dependency on #1022.

## Decision

### One scenario, optional delivery

Use `backends/_raes_scenario_resolution.py:resolve_scenario_bundle()` and
`ScenarioBundle`/`PackIdentity` as the scenario source seam. The default full
TechVault pack, its admitted RAES plan,
component definitions, internal addresses, ports, and workflow are shared.
Delivery may add platform enforcement and ingress without rewriting the
scenario. A role profile selects authority; it does not select a reduced lab.
`guided-purple-v1` remains a distinct fixture, not the appliance input source.

Evolve the existing participant reference/lock contracts to bind a validated
pack identity rather than inventing another scenario manifest or copying the
pack into a fake catalog entry. Preserve project-tree references for existing
fixtures through an explicit versioned source choice. Resolve content against
the bundle root, never a coincidentally matching project-relative file.
Preserve the single admission handoff in `core/lab.py`; consumers use that
admitted result instead of separately planning a different deployment.

Ordinary packaged `aptl lab init` and rootful `aptl lab start` require no
appliance descriptor, VM, kiosk, release signer, or nested virtualization.
Workbench assembly must accept trusted local deployment inputs as well as
appliance inputs, rather than requiring `ApplianceWorkbenchSettings` everywhere.
The browser remains a supported participant surface with real MCP backends
and authorized browser routes. Bookmarks alone do not prove those routes work.

### Restricted SSH-carried stdio

Host Claude Code and Codex launch an SSH transport process that carries MCP
stdio to a dedicated guest dispatcher. MCP servers, lab credentials, capture,
Docker operations, and local-artifact access remain guest-side. This reuses
`aptl-mcp-common` and the MCP SDK's stdio framing, without adding HTTP auth to
every MCP or exposing an operator API. The host client retains its own provider
authentication. It is an unmanaged client: APTL does not claim to sandbox its
host tools, provider traffic, or user-managed integrations.

The concrete transport contract is:

- A dedicated public-key-only guest account/listener runs a management-owned
  forced dispatcher. A separate transport key binds a caller, seat, instance
  generation, authorized role, and server set. Enrollment/revocation is a
  trusted management operation. Possession of an access record or knowledge of
  a seat ID grants nothing. Neither a lab SSH key nor provider auth is reused.
- The forced command is fixed and operator-owned. Parse an exact, bounded
  selector containing protocol version, expected instance/generation, and
  server ID; never execute `SSH_ORIGINAL_COMMAND`. Resolve authenticated key
  identity from trusted sshd context, not a requested username, role, or env
  variable. Select executable, working directory, and minimal environment from
  the admitted guest binding. Never accept arbitrary paths, endpoints, or argv.
  The forced dispatcher runs as a trusted guest management service identity.
  Participants cannot log into that identity or execute arbitrary guest commands.
  The dispatcher supplies only the selected backend's service credentials;
  guest Docker authority remains behind its role and protocol admission gates.
- Enforce `restrict` key restrictions plus sshd forwarding denial, no PTY,
  tunnels, agent/X11 forwarding, user rc, user environment, password fallback,
  SFTP/SCP, or interactive shell. A forced command alone does not disable
  forwarding. Keep account startup files and authorized-key policy outside
  participant write authority; validate the effective sshd configuration.
- Generated SSH invocation uses a fixed executable and argv, batch mode,
  explicit identity, strict pinned host-key verification, and an isolated
  generated SSH configuration. Do not inherit user proxy commands, agent keys,
  connection multiplexing, or automatic host-key enrollment. Disable ambient
  environment forwarding. The launcher supplies the authenticated host-key
  fingerprint; a key discovered through the same untrusted endpoint is not a
  trust anchor. Key material never appears in argv, URLs, or client config.
- Before spawning a backend, validate the key grant, role, current generation,
  active scenario/run, guest daemon/project ownership, backend identities,
  required capture readiness, and admitted boundary policy. Enforce the exact
  role tool set on both listing and calls at the guest MCP dispatch boundary;
  reject direct calls to hidden tools and unapproved protocol capabilities.
  Use the existing role inventory as the single authority definition.
- Each connection owns its MCP process and sessions. Bound connections,
  messages, output, idle time, and operation duration. Associate all calls with
  the server-owned caller/seat/run binding; clients cannot choose capture paths
  or overwrite correlation identity. Keep stdout exclusively MCP protocol.
- Revocation, expiry, role transition, instance replacement, or loss of required
  identity/capture invalidates admission and terminates affected live sessions,
  including descendants and SSH sessions opened by MCP. Removing a public key
  only prevents new SSH logins. Check authorization for each call and stop
  in-flight work on revocation. Record incomplete cleanup and block reuse.
  EOF, cancellation, and timeout follow the same bounded cleanup contract.
  Never retry a possibly executed mutation automatically after disconnect.

Browser role switching uses the same grant and revoke-before-replace rule as
CLI access. A participant cannot acquire blue authority merely by selecting
`blue` in a URL or modifying config. A purple workflow may grant a deliberate
transition; it does not combine role credentials in one process. Provider
credentials for an optional guest-managed agent retain their existing separate
source/lease lifecycle; host CLI access must not invoke that acquisition path.

OpenSSH documents [forced-command and forwarding controls](https://man.openbsd.org/sshd_config)
and [restricted keys](https://man.openbsd.org/sshd.8). These are mechanisms to
configure and test, not evidence that an arbitrary SSH account is a narrow API.

### Client configuration and private discovery

Generate each client's native project configuration from explicit instance,
generation, role/server grant reference, endpoint, and pinned key identity.
Claude uses project `.mcp.json`; Codex uses project `.codex/config.toml` in a
trusted project. Both support stdio command/args, but their shapes and trust
prompts differ. Preserve their normal trust/approval controls and user-owned
provider login. See the [Claude MCP configuration reference](https://code.claude.com/docs/en/mcp)
and [Codex MCP configuration reference](https://developers.openai.com/codex/mcp).

Reuse `core.lab._sync_mcp_config_keys()` as the incumbent selective-update
behavior, not as a host-seat credential exporter: it writes guest service
secrets and is not safe to run on the outer host for this purpose. Extend the
existing rendering boundary with client-specific serializers and one common
validated binding. Preserve unrelated settings and manual server entries,
including edits to formerly generated entries. Update only provably owned,
unchanged entries; report conflicts rather than overwriting. Reject malformed
or ambiguous documents, duplicate keys, identity mismatch, and stale endpoint
generations. Use private atomic writes with concurrent-edit detection; do not
partially publish a new binding and old configuration. Generated state is
ignored, not committed to the project or installed into global user config.

The private access record is a versioned discovery projection beside the
existing seat contract, not a replacement `SeatRecord`, release manifest,
authorization grant, or public status response. Its required content is:

| Content | Meaning and validation |
| --- | --- |
| Owner, seat, instance and generation | Stable management-issued identity; reset/replacement invalidates prior bindings. Bind guest boot identity as well; names alone are insufficient. |
| Guest deployment | Bound daemon ID, validated Compose project identity, scenario pack identity, and full native container IDs for referenced services. Verify ownership through `DeploymentBackend`, including replacement races. |
| Endpoints | Distinct guest-side endpoints and outer transport/browser endpoints with protocol and port; explicitly map each outer endpoint to its guest service. Record the transport host-key fingerprint. Never infer equality from matching port numbers. |
| Observation | UTC observation time, observation identity/generation, and bounded freshness policy. An old or future-dated observation cannot authorize connection. |
| Lifecycle | Project `SeatLifecycleState` and invalidation reasons; only a fresh ready binding is eligible for subsequent authorization. Stopped/reset/tainted/failed state cannot retain usable access. |

Use existing strict Pydantic, safe-path, atomic persistence, and canonical JSON
patterns in `appliance/seat/{models,persistence}.py` and `utils/pathsafe.py`.
Files and parent directories are owner-only from creation; refuse links,
foreign ownership, unsafe paths, and replacement races. Record no credentials,
raw inspect output, evidence, or provider state. #868 owns this schema and its
producer/consumer validation; #1022 owns durable live observation and lifecycle
publication. Discovery never substitutes for the guest's authorization check.
Do not copy `ContainerSnapshot.image_id` into a full container identity field:
the current snapshot populates it from the `docker ps` row ID, which can be
truncated. Obtain and verify the full container ID through backend inspection;
keep container identity, OCI image identity, and archive digest distinct.

### Complete inputs without premature release qualification

Extend `ParticipantAssetLock`'s content-addressed inventory and coverage
validation to describe the full package closure. The input report is usable
without a VM and makes no boot or production-release claim. Release/launch
contracts reference its digest; they do not reproduce its entries.

| Input boundary | Canonical source and completeness requirement |
| --- | --- |
| Python | APTL wheel plus target-platform wheel closure from `uv.lock` and existing hash-pinned `requirements/` exports, including selected extras, RAES, and `raes-env-packs`. Verify every selected wheel's hash, ABI/platform, version, and dependency satisfaction; one matching APTL filename is insufficient. |
| Project and pack | `hatch_build.py`, `_asset_manifest.py`, and `core.assets.materialize()` own tracked assets and generated-state exclusions. `ScenarioBundle` owns the separately packaged pack. Include actual build/mount inputs; never repair missing pack content using another checkout or manual fixup scripts. |
| Built frontend and MCP | Use `web/package-lock.json`, `web` build scripts, and `mcp/build-all-mcps.sh` with each lockfile. Stage executable build output and runtime dependency closure, including the built common library. The normal tracked-source bundle excludes `build`, `dist`, and `node_modules`; do not remove those exclusions to scoop up developer state. |
| OCI and runtime helpers | Derive scenario/service identities from the admitted realization, plus boundary/capture/seed helpers and declared orchestration child images. Bind platform-specific immutable identities and archive hashes separately. Include runtime package/source inputs needed by image-free realization; top-level Compose images alone are not closure. |

Preserve `offline.py`'s closed outer archive and no-follow deterministic archive
utilities while strengthening nested archive/member/hash validation. Reject
traversal, links, special files, duplicate entries, missing runtime dependencies,
and unlisted payload content before extraction or installation. Account for
guest OS, Node, SSH, Docker, and helper runtime prerequisites in the builder
input contract. Resolve the existing first-boot `--scenario` catalog assumption
through the canonical source seam, not an appliance-specific scenario alias.

Full TechVault includes powerful SOC services and child workloads. Preserve
the exact admitted orchestration-authority exception from the issue #949
preflight; do not remove those services to make qualification pass or treat a
read-only Docker socket mount as restricted authority. A sealed build remains
ineligible until its real containment can be proved.

## Cross-cutting validation and reuse

| Layer and incumbents | Required passage |
| --- | --- |
| Scenario/config admission: `core/config.py`, `core/scenario_bundle.py`, RAES admission, ADR-025/051/053 | Closed config and source variants, validated pack content, one admitted plan, and existing capability/authority checks. No arbitrary envelope fields in `aptl.json`, fallback scenario, or parallel RAES schema. |
| Environment/secret binding: `core/env.py`, `raes_stateful_realization.py`, deployment `_compose_stateful_realization.py`/`_compose_realization.py` | Reuse `load_dotenv`, `EnvVars`, placeholder checks, exact declared output/consumer/delivery shapes, valid env names, and value validation. A flat env dictionary or new credential alias must not bypass generated-artifact consumers. Keep transport keys outside service-env contracts. |
| Workbench/MCP config: `profiles.py`, `agent._load_server_config()`/`_valid_server_entry()`, common `config.ts` | Internal managed config currently permits exactly `mcpServers` and command/args/env entries. Keep it distinct from user-managed client documents; do not add discovery metadata to that closed shape. Explicit guest env must include required dynamic ports and aliases, disable dotenv discovery, and reject unresolved substitutions; common currently warns about missing variables. |
| Authentication/authorization: workbench route assembly, `api/session.py`, `api/middleware/bff.py`, `api/deps.py`, MCP `server.ts` and handlers | Keep operator API/session token separate from participant and transport auth. Preserve Host/Origin/CSRF/WebSocket controls where applicable. Bind browser caller to grants; authorize MCP calls before handlers execute. SDK request-shape parsing and `tools/list` equality alone do not enforce roles or tool argument safety. Reuse canonical handler validation and reject unvalidated arguments. |
| Endpoint/TLS/SSH: `core/endpoints.py`, snapshot runtime ports, `host_ports.py`, common `endpoint-url.ts`, `http.ts`, SSH manager, ADR-034/040 | Distinguish scenario target port, guest publication, and outer mapping. Use observed endpoints with ownership checks, verified service CA and SSH host keys, same-origin HTTP endpoint constraints, and contained guest paths. No insecure TLS, arbitrary tunnels, or outer-host `DOCKER_HOST`. |
| Boundary/release: `appliance_boundary*.py`, deployment boundary compiler/realization, `appliance/{models,release_models,launch,release_validation}.py` | Version incompatible shape changes and update every reader, writer, fixture, policy digest, and signature binding. Model authorized MCP ingress explicitly, separately from recovery. Validate a trusted guest-to-outer mapping instead of relaxing listener equality or loopback rules globally. Keep default-deny readback, negative probes, and fatal admission. |
| OS authority and lifetime: `_docker_endpoint_binding.py`, `DeploymentBackend`, `workbench/process.py`, ADR-041/042/050 | Revalidate guest socket/daemon and owned full native IDs; dispatcher has no participant shell or outer socket. Reuse bounded process cleanup, but prove descendants stop. Preserve required capture ownership/finalization before admitting actions or reporting success. |
| Persistence, errors, telemetry: `utils/pathsafe.py`, `RunStorageBackend`/`LocalRunStore`, `get_logger`, OTel, Python/TypeScript `redact()` | Retain guest run identity, separate access audit from scenario evidence, and record safe caller/seat/role/generation, decisions, codes, counts and timings. Map failures to existing workbench errors, MCP envelopes, `LabResult`/`StartupDiagnostic`, boundary findings and seat errors. Never emit raw validation inputs, SSH stderr, keys, env, paths, or backend error bodies. No duplicate exception tree. |

ADR-027's asynchronous best-effort SIEM hook is observability, not an
authorization or required-capture gate. Redact protocol results and diagnostics
before they leave the guest; capture opt-outs cannot disable control-plane
redaction. Do not promise redaction makes arbitrary raw artifacts safe. Release
only authorized tool results/projections and existing classified exports.

## Consequences and implementation boundaries

The extension explicitly permits host clients, user-owned provider auth,
transport credentials, private discovery/configuration, and authorized MCP
results on the host. It does not permit host lab credentials, raw evidence
synchronization, a guest shell, Docker proxy, or arbitrary file API. Browser
and guest-managed agent support remain available. Host CLI replies may enter
the user's provider context; do not claim guest-only confinement of those
authorized replies or complete capture of host-side reasoning.

Parameterize the existing delivery seam with scenario source identity,
instance/generation, role grant, client serializer, guest/outer endpoint mapping,
and transport version. Ports and paths are instance inputs, not edits to
TechVault. Future hosted delivery or another client consumes those bindings;
it must not require another scenario, role registry, or lifecycle engine.

Whole-repository reconciliation includes the owners in the tables, the
participant profiles/readiness/qualification models, `appliance/guest/`,
`appliance/seat/`, CLI adapters, Compose/container/config assets, build locks,
`.github/workflows/`, `.ground-control.yaml` boundary path coverage, and the
workbench, boundary, release, and seat-launcher documentation. On adoption,
reconcile ADR-049's conflicting policy through this partial supersession and
update the #821/#823 preflight assumptions. ADR-052/055/057/058 are related
proposals, not evidence that their enforcement already exists.

#868 must prove packaged full-TechVault rootful deployment, the real workbench,
input completeness and hashes, both native client configurations, and actual
client-driven MCP execution against real backends. Record client versions and
separate provider-authenticated client runs from SDK/protocol/config checks.
The controlled rootful integration environment supplies real deployment
identity and enforces the transport contract without claiming a sealed seat.
Appliance boundary admission still requires its authenticated host observation;
do not fabricate that observation or add a production test-mode bypass.
Test denied tools/roles, wrong owner/seat/daemon/container/host key, revoked and
expired grants including live connections, changed endpoints, partial writes,
manual config preservation, unsafe paths, capture loss, and cleanup failure.
Use existing `tests/test_participant_workbench*`, `test_mcp_config_example`,
appliance/boundary/package tests, `validation/participant_mcp_smoke.py`, and
`validation/mcp_protocol.py`; extend coverage without duplicating validators.

Relevant pytest/vitest suites and all dependents of changed MCP common code
must pass. `.ground-control.yaml` defines the bounded completion commands;
`.gc/plan-rules.md` requires clean fresh-machine rootful lab validation for
Compose/Dockerfile/config changes and `pre-commit run --all-files`. Protocol
fixtures, a TCP connection, and synthetic qualification flags are not substitutes
for client/backend execution. Unavailable provider execution is a missing
acceptance result, not a passed test.

#1022 owns actual image construction, boot mounts/key wiring, allocated host
ports, concurrent-seat lifecycle, offline VM boot, nested KVM, real boundary
and telemetry probes, two users with both clients, signed independent-machine
qualification, recovery, and publication. Keep `verify_release_directory()`
and `ApplianceDrillReport` strict; do not add a bypass or fabricate a golden disk
to let #868 close. It supplies validated inputs and implemented software
contracts, while production release remains gated on #1022 evidence.
#1053's rootless unwind is independent. The software input and transport
contracts are implemented in `appliance/inputs.py`, `workbench/guest_binding.py`,
`workbench/relay.py`, and `cli/mcp_access.py`; they do not certify a VM release.
