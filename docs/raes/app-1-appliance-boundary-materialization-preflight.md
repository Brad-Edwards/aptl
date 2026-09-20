# APP-1 Appliance Boundary Materialization Preflight

**Scope update (2026-09-20):** APP-1 internal security review/implementation is
tracked in #1127, not a #1022 delivery gate. Current seats use the explicit
[ADR-060 VM-only contract](../adrs/adr-060-vm-only-seat-containment.md).
The inner-boundary guidance below applies to that follow-up, not as permission
to alter ordinary TechVault traffic in VM-only seats.

This note is the architecture preflight for APP-1 / issues #822 and #1022. It narrows
[ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md) for boundary
materialization and verification; it is guidance, not an implementation plan.
The #1022 revalidation below reflects the current repository. Consume #868's
merged contracts and [ADR-059](../adrs/adr-059-canonical-techvault-delivery-and-host-mcp-access.md);
#1053 remains independent. No additional ADR or parallel boundary model is needed.

## Authority And Contract Boundaries

APP-1 composes two policy authorities. It must not merge them into an
appliance-owned topology model.

| Authority | Owns | Must Not Own |
| --- | --- | --- |
| Admitted RAES realization | Scenario nodes, networks, links, domain bindings, infrastructure ACLs, services, runtime publications, and exercise effects | Participant, management, egress, physical-host, recovery, or Docker-daemon policy |
| Signed appliance platform policy | Participant/management/egress placement, default-deny inter-zone baseline, controlled external destinations, guest-Docker authority, guest-host publications, and the outer host/recovery contract | Scenario node identity, red/blue/target membership, scenario service lists, target subnets, or a copy of RAES ACLs |

The effective policy is the intersection of those authorities. Platform policy
may further deny a RAES flow but cannot add a scenario flow; admitted RAES
policy cannot weaken host, management, egress, metadata, Docker-authority, or
participant-ingress controls. A conflict is a fatal admission/materialization
diagnostic, never a precedence guess.

RAES remains authoritative through `ACLRule`, SDL parsing and semantic
validation, scenario instantiation, the compiler's `ProvisioningPlan`, planner
diagnostics, and `RuntimeManager`. APTL must lower the admitted ACL values into
the existing `AptlRealization` to `DeploymentRealizationSpec` seam. It must not
add an APTL ACL authoring schema, parse the scenario file a second time, or
derive policy from Compose networks.

The backend-facing typed value must retain the owning RAES resource address,
source and destination references, direction, action, protocol, ports, and
deterministic authored order. Descriptive prose is not policy. The provider
boundary must reject malformed direct `ProvisioningPlan` payloads and any
direction, endpoint form, action, protocol, port combination, wildcard, or rule
precedence it cannot enforce exactly. This is provider capability validation,
not a duplicate SDL schema.

`create_aptl_manifest()` now declares `supports_acls=True`; typed ACL lowering,
compilation, and helper readback already exist. Preserve capability honesty:
this claim covers the implemented subset, not arbitrary ACL semantics or proof
of appliance readiness. Unsupported endpoints, protocols, precedence, or
backend capabilities must still fail closed before mutation.

The platform half is one versioned, signed appliance-boundary policy contract.
It is payload policy, not mutable `aptl.json` configuration and not an
environment-variable bag. It carries only platform-owned zone classes,
allowed participant ingress and recovery exposure, controlled egress
destinations and purposes, Docker-authority constraints, resource limits, and
policy version/identity. Egress credentials remain in the ADR-049
secret-bootstrap channel and never enter this contract.

## Materialize Then Observe

The existing interpret-then-driver design remains binding:

1. RAES parsing, planning, manifest gating, and APTL provider validation produce
   one complete typed desired boundary without native side effects.
2. `DeploymentBackend.realize()` applies the typed scenario realization and
   appliance policy through narrow backend operations using the existing
   project scope, runner, argv-list, timeout, logging, and `LabResult`
   behavior.
3. Provider readback produces one fresh, redacted boundary inventory. Desired
   data, generated firewall text, a successful command, and a running
   container are not observed enforcement.
4. The desired-versus-observed gate blocks a successful RAES `ApplyResult` and
   appliance readiness on any missing, extra, ambiguous, stale, unsupported,
   or unverifiable boundary fact.

All validation that can be performed without side effects must finish before
the first mutation. Enforcement must have a deny baseline before an untrusted
workload can run. Policy updates must be atomic or staged so a failure retains
the last verified deny posture; rollback must never reopen traffic.

`_compose_base_substrate.py` now creates image-free nodes on admitted networks,
attaches remaining declared networks while stopped, then starts them. Preserve
that ordering and prove the deny floor exists before workload execution;
network-before-start alone is not firewall-before-start. No temporary default
bridge or general egress is permitted. Appliance startup uses staged inputs
only, without downloads, package resolution, image pulls, or builds.

Likewise, a Docker network marked `internal`, a loopback bind, a listener, a
successful TCP probe, and a firewall authorization are distinct facts. None is
proof of another. Multi-homed ordinary workloads must have forwarding disabled;
only a platform-owned gateway may route, resolve, proxy, or inspect across
zones.

## Fail-Closed Boundary Inventory

APP-1 needs one versioned appliance-boundary inventory because neither existing
inventory surface has the required semantics:

- `RuntimeSnapshot` is the RAES realization/SEM-218 disclosure surface.
- `RangeSnapshot` is a broader operational snapshot whose capture failure is
  deliberately non-fatal under ADR-030.

The boundary inventory is a security verdict, so it may reuse their normalized
backend observations but must not be represented as an optional
`RangeSnapshot` section or a second RAES runtime snapshot. Image qualification
and every appliance start consume the same contract and verifier. A
qualification report proves the qualified payload; it is not fresh evidence
for a later boot.

The inventory must carry bounded, non-secret facts:

- schema, policy, payload, RAES plan, and verifier identities/digests;
- qualification/start phase plus a fresh appliance-boot and guest-Docker
  instance identity;
- desired policy digest and observed enforcement mechanism/version;
- observed networks, zone classifications, node attachments, routing and
  forwarding disposition;
- guest-host publications and separately supplied physical-host forwards and
  listeners;
- controlled DNS, time, proxy, and egress disposition, including denied
  private, link-local, metadata, venue, host, and arbitrary-internet classes;
- Docker authority holders, socket/API endpoint identity, privileged/container
  authority features, and proof that the daemon is the disposable guest
  daemon;
- positive and negative probe verdicts, stable finding codes, observation
  completeness, and the final pass/fail decision.

It must omit credentials, authorization headers, environment values, raw
Docker inspect payloads, raw firewall/routing output, command lines, host
absolute paths, generated secret-bearing config, and evidence bytes.
Structured serialization must pass through `redact()` before logging,
persistence, API projection, or packaging. Runtime persistence uses the
existing `RunStorageBackend`/`LocalRunStore` boundary; qualification packages
reference the same canonical redacted bytes and digest rather than defining a
second report shape.

The guest backend cannot observe the physical host from inside the security
boundary. The appliance envelope/launcher therefore supplies an authenticated,
fresh outer-host observation using the same inventory contract. Missing host
observation, an unrecognized observation capability, or a boot/daemon identity
mismatch is fatal in supported appliance mode. Issue #824 may provide the
launcher mechanics; APP-1 must define and require the input rather than infer
physical-host safety from guest loopback bindings.

## Required Existing Cross-Cutting Owners

| Concern | Canonical incumbent to extend or consume |
| --- | --- |
| RAES shape and semantics | `raes.infrastructure.ACLRule`, `parse_sdl_file()`, semantic validation, instantiation, compiler, `ProvisioningPlan`, planner diagnostics, `RuntimeManager`, and RAES `Diagnostic` |
| Capability honesty | `src/aptl/backends/raes_manifest.py`, provider subset validation, and selected-backend enforcement/readback |
| Interpretation | `raes_realization.py`, `raes_realization_values.py`, `raes_realization_networks.py`, `raes_realization_model.py`, and `raes_diagnostics.py` |
| Apply and observation | `AptlProvisioner`, `observe_realization()`, `ObservedResource`, `snapshot_after_apply()`, and RAES's existing realization-disclosure gate |
| Deployment authority | `DeploymentRealizationSpec`, `DeploymentBackend`, `DockerComposeBackend`, SSH transport parity where supported, Compose project labels, bounded runner calls, and `BackendTimeoutError` |
| Runtime inventory | Backend host/container/network inventory, `ContainerSnapshot`, `NetworkSnapshot`, `container_networks()`, `list_container_snapshots()`, and runtime port normalization |
| Host exposure | `runtime.network.published_ports`, `DeploymentPublishedPort`, `core.host_ports`, ADR-034, ADR-036, and `tests/test_docker_compose_port_bindings.py` |
| Startup workflow | `core.lab`'s flat `_LAB_START_STEPS`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, and ADR-030/031 |
| Config and secrets | Strict `AptlConfig`, `load_dotenv()`, `EnvVars`, placeholder checks, generated-state containment, ADR-025/028/029, and the ADR-049 bootstrap channel |
| Persistence and redaction | `RunStorageBackend`, `LocalRunStore`, evidence/content-store writers, `RangeSnapshot.to_dict()`, `redact()`, `get_logger()`, and ADR-012/029/044 |
| API/auth if projected | Management-only FastAPI assembly, Pydantic schemas, `verify_token`, BFF Host/CSRF/session controls, narrow HTTP/WebSocket errors, and ADR-039/040 |
| Repository gates | `.ground-control.yaml`, `.gc/plan-rules.md`, pytest, pre-commit, RAES static/live gates, Compose security tests, and clean-lab validation |

Do not introduce an appliance-wide exception hierarchy, repository layer,
policy service graph, second redactor, second readiness taxonomy, or generic
Docker/firewall command passthrough. Stable RAES/provider failures use
`Diagnostic` plus `render_raes_diagnostics()`. Backend failures use
`LabResult`/`BackendTimeoutError`. At CLI/API/web edges the outcome is
`StartupOutcome.FAILED` with bounded, redacted messages. Boundary uncertainty
is not `DEGRADED_USABLE` or `DEGRADED_UNUSABLE`.

## Security Layer Passage

- **RAES admission:** closed-world SDL/Pydantic shape, reference validation,
  variable instantiation, semantic checks, planner capability checks, and
  planner diagnostics run before APTL translation. APTL never accepts raw ACL
  YAML or treats a manifest flag as proof of enforcement.
- **Provider validation:** the interpreter shape-checks public plan mappings,
  resolves every endpoint to one admitted resource, preserves rule order, and
  rejects unsupported IPv4/IPv6, protocol, direction, port, wildcard, and
  precedence semantics before backend mutation.
- **Platform-policy integrity:** the payload manifest verifies the boundary
  policy version and digest. Unsupported schema versions, unsigned policy,
  unknown delivery mode, or an unavailable enforcement/observation capability
  fail closed.
- **First-party config:** `AptlConfig(extra="forbid")` remains durable
  non-secret operator configuration. It may select a supported delivery mode or
  policy reference only where ADR-049's envelope permits; it does not mirror
  policy rules, zones, RAES topology, or destination lists.
- **Environment and secret binding:** existing `.env` and service-local strict
  parsers remain authoritative for current secrets. Appliance/model credentials
  use the narrow bootstrap parser, never ACL fields, policy documents, Docker
  labels, frontend state, URLs, or inventory.
- **Deployment/OS enforcement:** every Docker, network, route, firewall,
  publication, mount, and inspect operation stays behind typed backend/envelope
  operations. Enforcement and observation cover IPv4 and IPv6, forwarding,
  DNS bypass, direct egress, metadata/link-local ranges, host/venue routes, and
  daemon identity. An unavailable kernel/backend feature is fatal.
- **Docker authority:** observed mounts, endpoints, namespaces, capabilities,
  devices, privileged flags, and daemon identity are compared with one exact
  platform allow-list. `/var/run/docker.sock` path matching alone is
  insufficient. Unknown holders, a host/remote daemon, a generic Docker proxy,
  or an uninspectable authority path fail closed.
- **Process exposure:** argv lists remain mandatory. Policy/secret material does
  not enter shell strings, process titles, healthchecks, exception text, or raw
  support logs. Firewall/routing command output is parsed inside the backend
  into bounded observations and never forwarded.
- **API/auth:** APP-1 adds no participant API. Any management inventory
  projection remains behind the existing operator auth/BFF/session/Host/CSRF
  boundary and returns a narrow redacted DTO. The participant gateway receives
  only coarse readiness, not the inventory or its raw findings.
- **Error envelopes:** stable finding/diagnostic codes and safe resource
  addresses cross RAES, core, CLI, and API boundaries. Raw exceptions, policy
  documents, subprocess output, and inspect payloads do not.
- **Persistence and observability:** redaction occurs before the first
  structured write. Logs/traces contain policy/payload digests, stable codes,
  counts, elapsed time, and verdict only. Opaque evidence remains governed by
  the existing evidence sensitivity/export boundary.

## Egress And Exposure Guardrails

Controlled egress is a platform gateway/proxy/resolver concern, never a
multi-homed Kali, target, DNS, Wazuh, or Suricata side effect. An exception is
typed by purpose, source platform class, destination authority, protocol/port,
resolution behavior, and failure disposition. Redirects, DNS rebinding, proxy
`CONNECT`, direct DNS/DoH, QUIC/UDP alternatives, IPv6, and provider addresses
that resolve into denied ranges must not bypass that decision. Secret material
is referenced from management state, not embedded in the exception.

Container-to-guest publishing and guest-to-physical-host forwarding are
separate inventory fields. RAES `Node.services` is listener intent;
`runtime.network.published_ports` is container-to-guest publication; the
appliance envelope alone owns physical-host participant/recovery forwarding.
None implies firewall authorization. In appliance mode, an explicit RAES
all-interface publication may still be rejected by platform policy even though
developer-local mode allows it.

ADR-059 requires full TechVault, including explicitly admitted management
orchestration. Reuse [issue #949's authority admission](../architecture/issue-949-orborus-control-authority-preflight.md)
and [issue #964's ownership receipts](../architecture/issue-964-backend-resource-ownership-preflight.md):
one graph-derived typed admission, the exact guest-local socket/daemon, effective
Compose validation, child-image closure, and observed owned children. Do not
remove required SOC services to make qualification pass or infer approval from
a static socket mount, self-authored label, read-only socket, or generic proxy.
The launcher, participants, and boundary helper receive no Docker socket.

The generic base substrate also requests host cgroup namespace access, a
writable cgroup filesystem, Linux capabilities, and sometimes unconfined
seccomp. Those are guest-host authority inside the appliance. The platform
contract must explicitly admit and observe every such feature per workload;
“inside a VM” is not blanket approval.

## #1022 Boundary Revalidation

These are implementation blockers found by source inspection, not claims of
live exploitation or VM qualification. Existing unit fixtures do not resolve
them. Image construction, publication, and VM lifecycle remain #1022's delivery
scope; this section constrains their use of APP-1.

### Preserve identity meanings and evidence provenance

- `seat/lifecycle.py`, `core/lab.py`, and
  `workbench/guest_binding.py` currently populate or compare `raes_plan_digest`
  with `participant_routes_digest`. Routes and the admitted infrastructure plan
  are different artifacts. Bind the actual admitted plan identity through the
  existing release/launch/boundary contracts; do not relabel one digest or
  recompute a second plan. Version incompatible contracts and update all
  producers, readers, signatures, fixtures, and qualification evidence together.
- The launcher uses the physical-host boot ID; guest startup and
  `GuestAdmission` use the guest boot ID in the same boundary field. Keep host
  boot, guest boot, overlay instance/generation, process start identity, and
  daemon ID distinct. Prove their association over an authenticated management
  channel bound to this launch. A content digest is integrity, not producer
  authentication. Public anchors belong in the read-only launch share;
  credentials do not.
- `stage_seat()` constructs completed host observations from planned endpoints,
  and `start_seat()` asserts forbidden-reachability success. Stage intent cannot
  be evidence of a later boot. Separate immutable launch intent from fresh
  evidence using the incumbent contracts; define their authenticated association
  without a circular requirement to know a post-boot digest before launch.
  Never overwrite a create-once descriptor or copy its old observation into a
  new generation. `observation_id_for()` omits completion, and the verifier
  recomputes it only for host-MCP policies: all audiences need equivalent
  provenance and coverage of verdict-bearing fields.
- `run_appliance_boundary_gate()` has a protocol and test adapter, but no
  production `materialize_and_observe_boundary()` implementation in this tree.
  The launcher calls the host-only check; MCP admission separately consumes
  supplied guest observations. Connect qualification and every start to the
  same complete verifier and real producer. Keep read-only per-call admission
  separate from materialization; an MCP request must not reinstall policy.
- `_append_probe_findings()` checks for some passing positive and negative
  probes per authority, not completeness against required crossings. Derive
  required coverage from admitted policy/capabilities, require unique probe
  identities and current source provenance, and distinguish blocked traffic
  from broken instrumentation or an unavailable destination. Unknown is fatal.
  Complete Docker-authority inspection must likewise precede accepting an empty
  holder list. Preserve kernel readback, atomic deny posture, and re-observation
  after drift; refreshing a timestamp does not refresh evidence.

### Keep outer transport separate from guest publications

`GuestPublication` and `BoundaryEndpoint` already validate loopback and typed
guest-to-outer mappings. `SeatEndpoint`/`SeatAccessRecord` already own host-MCP
discovery. Extend those owners and the versioned seat launch binding for every
approved audience; derive QEMU argv, kiosk URLs, persisted state, and client
configuration from one validated mapping collection. Duplicate physical bind
tuples must fail even if audiences differ. Preserve IPv4/IPv6 identity rather
than rewriting `::1` to `127.0.0.1`, as the current listener parser does.

The current QEMU adapter omits the guest address in `hostfwd`, while the policy
permits guest loopback only. QEMU documents an omitted address as the guest's
DHCP address, so this is not proof of a path to a loopback service. Its user
network also has host, DNS, and dual-stack behavior beyond the declared ingress.
The adapter must prove an explicit, narrow ingress path and controlled egress
or reject that capability; do not change services to wildcard binds to make a
probe pass. Any forwarding bridge must be platform-owned and observed, without
changing scenario ports. See [QEMU network options](https://www.qemu.org/docs/master/system/invocation.html).

Host coexistence requires proving ownership of every seat listener and absence
of unauthorized seat-owned exposure, not filtering all host listeners down to
expected ports. The current `map_publications_to_listeners()` discards extras;
preserve the complete seat-owned inventory for the gate. Unrelated Docker and
listeners are not authority violations, but inaccessible ownership information
is not success. Reuse endpoint parsing from `core/host_ports.py`, not its
check-then-close allocation as a concurrency reservation. Allocation needs
cross-user coordination through bind outcome; a per-seat/user lock cannot
serialize competing users. Per-seat lifecycle locking, owner-verified process
handles, resource reservations, and failure cleanup must not affect another
seat or unrelated host resources.

### Additional cross-cutting passage for seat delivery

| Layer / incumbent | Required passage |
| --- | --- |
| Release/input admission: `appliance/{inputs,offline,build,manifest,launch,release_validation}.py`, `ParticipantAssetLock`, `_asset_manifest.py`, `hatch_build.py` | Consume #868's canonical full-TechVault inputs, exact dependencies and helper/child-image closure. Preserve safe archive extraction, signed byte identity, offline boot, separate development trust, and real independent-machine qualification. Transport chunking must authenticate reconstruction without changing canonical release identity. |
| Config/env shapes: `core/config.py`, `core/env.py`, `raes_stateful_realization.py`, deployment generated-artifact consumers | Preserve strict config, declared output/consumer/delivery shapes, env-name/value and placeholder checks. Outer mappings do not belong in `aptl.json`, Compose env overrides, or scenario topology. |
| MCP config/auth: `workbench/{agent,access,dispatch,guest_binding,preparation,access_clients,client_files}.py`, common `config.ts` and `server.ts` | Internal managed config accepts its closed `mcpServers` shape; host native config/discovery are separate serializers. Use the existing minimal guest environment with dotenv discovery disabled and resolved aliases/ports. Reuse key-bound grants, role/tool checks, pinned SSH host keys, per-call guest/capture admission, revocation, and bounded descendant cleanup. Discovery grants no authority; host provider auth stays user-owned. |
| OS/process boundary: `seat/{vm,exposure,prereqs}.py`, `_docker_endpoint_binding.py`, `workbench/process.py` | Verify effective KVM access, available concurrent resources, QEMU support, selected guest daemon, and owned native IDs. Fixed argv alone does not prevent QEMU comma-option injection through paths: validate/encode values for QEMU's own grammar. No secrets in argv, URLs, environment dumps, public shares, or diagnostics; no arbitrary shell/forwarding passthrough. |
| Persistence: `seat/persistence.py`, `utils/pathsafe.py`, `_atomic_write`, `core/lifecycle_guard.py`, `RunStorageBackend` | Reuse private atomic/no-follow I/O and lock semantics; prove ownership, bounded reads, ancestor containment and concurrent replacement safety rather than assuming mode bits suffice. Keep seat state, access discovery, and run evidence distinct. Invalidate access on stop/failure/reboot; reset revokes old grants, pins, and live sessions. |
| Errors/projections: `SeatLauncherError`, `WorkbenchConfigurationError`, `LabResult`/`StartupDiagnostic`, RAES diagnostics, API schemas/BFF | Translate native failures once at the owning edge to existing stable codes. Never emit raw Pydantic input errors, subprocess stderr, inspect data, paths or secrets. Operator projections retain token/Host/Origin/CSRF/session controls; participant output remains coarse. Use `get_logger()` and Python/TypeScript `redact()` before external serialization. |
| Repository/qualification gates: `.ground-control.yaml`, `.gc/plan-rules.md`, `.github/workflows/{checks,release-please}.yml`, appliance/seat/boundary/host-MCP tests | Extend current tests and release workflow. Require real KVM boot, two concurrent users, forbidden crossing probes, stale/replaced identity rejection, and isolation through reset/stop; mocked argv/process tests are not those proofs. Common MCP changes require all dependents; image/Compose/config changes require fresh-machine clean-lab validation. Keep GRC path ownership accurate for appliance, workbench, guest assets and helper containers without inventing unsupported adapter surface names. |

## Extensibility And Whole-Repository Scope

The extensibility seam is the versioned pair of a platform boundary policy
reference and a boundary-observation adapter carried by ADR-049's appliance
envelope. A future local hypervisor, hosted seat gateway, model provider, or
approved update mirror varies that pair and its declared capabilities; it does
not fork scenarios, Compose files, API DTOs, frontend bundles, or the verifier.
Scenario variation remains entirely in admitted RAES resources.
For #1022, the concrete parameter is a collection of audience/protocol/outer
endpoint/guest endpoint mappings plus adapter observation capabilities, bound
to the current instance generation. An additional approved audience or future
hypervisor extends that seam, not scenario artifacts or a second verifier.

Implementation must reconcile all repository/runtime surfaces that can grant or
observe authority:

- the locked RAES dependency in `pyproject.toml`/`uv.lock`, backend manifest,
  RAES adapter, provisioner, observation, diagnostics, and materializer;
- deployment realization DTOs, backend Protocol/concrete backends, Compose
  generated overrides, runner/timeout/error behavior, network reconciliation,
  base-container startup, cleanup, and runtime inventory;
- `docker-compose.yml`, `aptl.json`, `.env.example`, MCP configs, container
  Dockerfiles, capabilities, devices, namespaces, socket/bind mounts,
  healthchecks, networks, publications, and guest Docker-daemon configuration;
- lab startup/readiness, snapshot/endpoint/host-port consumers, run/evidence
  persistence, export, redaction, logging, and telemetry;
- management API/web projections if any, participant route isolation, MCP
  transport/config only where internal endpoint or egress placement changes;
- guest firewall/routing/DNS/proxy state and the external launcher/hypervisor
  listener, forwarding, device-sharing, and recovery observation supplied by
  issue #824;
- deployment/security/workshop/recovery documentation, `.ground-control.yaml`
  boundary declarations, static policy tests, backend unit/integration tests,
  qualification/live gates, and the clean-lab completion gate required for
  Compose/container/config changes.

## Gotchas And Anti-Patterns

- Do not conflate service declaration, listener state, Docker publication,
  firewall authorization, route existence, probe success, and end-to-end
  reachability.
- Do not flatten RAES ACLs and platform policy into one rule list with guessed
  precedence, or let platform policy name current red/blue/target nodes.
- Do not treat `internal: true`, network attachment, loopback, NAT, CORS, TLS,
  or the VM boundary as enforcement proof.
- Do not accept a policy because generated rules match desired text. Read back
  effective kernel/provider state and run negative probes from the relevant
  source zones.
- Do not start workloads on Docker's default bridge and remove it later. Do not
  permit temporary internet access for package installation.
- Do not inspect only checked-in Compose. Generated overrides, image-free
  `docker run` containers, runtime drift, outer-host forwarding, IPv6, and
  alternate Docker endpoints are part of the observed surface.
- Do not reuse a qualification inventory as runtime readiness, accept a prior
  boot's report, or let incomplete observation pass with a warning.
- Do not copy `RangeSnapshot`, endpoint registry, RAES runtime snapshot, or
  Docker inspect schemas into the boundary inventory. Consume their normalized
  facts and retain distinct semantics.
- Do not put policy or credentials in argv, environment-driven rule fragments,
  Docker labels, exception messages, support bundles, or participant-visible
  status.
- Do not advertise `supports_acls=True` until apply, observation, failure
  atomicity, and live positive/negative conformance are all real.

## Non-Goals And Implementation Boundary

- APP-1 owns the shared policy and fatal verifier, not a second builder,
  launcher, hosted fleet, participant UI, or model agent. #1022 repairs and
  integrates the existing #823/#824 builder and launcher under these contracts.
  This preflight changes guidance only and authorizes no artifact publication.
- Do not redefine RAES ACLs, scenario topology, domain membership, services,
  exercise effects, participant contracts, or evidence contracts.
- Do not replace Docker/Compose as the inner deployment mechanism or make the
  outer VM a RAES node provider.
- Do not make developer-local Compose satisfy the supported participant
  appliance contract; it may remain an explicitly separate mode.
- Do not redesign operator API auth, MCP tool schemas, run archive layout, or
  evidence acquisition. Use ADR-059's restricted host-MCP transport and existing
  lifecycle/reset contracts; version necessary identity/mapping corrections
  instead of creating a parallel workflow.
- Do not broaden Kali/target egress, preserve unsafe socket-dependent optional
  features, or weaken a required control because an enforcement or observation
  mechanism is unavailable.
