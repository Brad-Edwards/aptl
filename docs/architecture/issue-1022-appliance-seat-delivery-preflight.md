# Issue #1022 Appliance Seat Delivery Preflight

**Current scope (2026-09-20):** [ADR-060](../adrs/adr-060-vm-only-seat-containment.md)
records the owner's VM-only decision. It supersedes this note's internal-zone
enforcement obligations for #1022. APP-1 and internal security move to #1127;
signed delivery, authenticated access, real lab QA and host/cross-seat isolation
remain required. Historical analysis below does not add those deferred features
back into the delivery scope.

This note sets architecture guardrails for repairing appliance construction,
real-VM startup, concurrent rootful seats, host CLI access, and public artifact
delivery. It is guidance, not an implementation plan. The GitHub issue is the
authoritative acceptance contract.

No new ADR is needed. [ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md)
already owns the disposable VM boundary, [ADR-059](../adrs/adr-059-canonical-techvault-delivery-and-host-mcp-access.md)
owns canonical full-TechVault inputs and restricted host MCP access, and the
issue #823 and #824 preflights own the signed release and outer lifecycle
adapter. Issue #1022 must finish and prove those decisions rather than replace
them.

Issue #868 is the merge prerequisite; its software contracts do not certify a VM.
APP-1 owns boundary enforcement, APP-2 owns participant qualification, and APP-3
binds their identities and evidence into the release. #1053 remains independent.

## Architecture Decisions And Guardrails

### Preserve one identity chain

The implementation must maintain one fail-closed identity chain:

`signed release -> launch descriptor -> overlay generation -> VM process ->
guest boot and Docker daemon -> host endpoint mappings -> access observation`

Each transition must be observed, not inferred. A matching seat name, live PID,
open TCP port, qcow2 filename, or cached access record proves none of the next
identity. Reset creates a new overlay identity, guest boot identity, transport
generation, host-key pin, grants, and observations. Stop preserves the overlay
but invalidates live readiness and discovery until the same instance is
re-observed. Recovery destroys the old overlay; it is not an in-guest repair.

Keep the existing concepts distinct:

- `ApplianceReleaseManifest` authenticates immutable release content.
- `ApplianceLaunchDescriptor` is the verified create-once projection supplied
  to one launch; it is not mutable seat state.
- `SeatRecord` is outer lifecycle metadata; it is not discovery or authority.
- `HostBoundaryObservation` and `GuestBoundaryObservation` are fresh evidence;
  they are not configuration.
- `SeatAccessRecord` is private, secret-free discovery; `CallerGrant` and the
  guest dispatcher binding establish authority.
- `LabResult` and `StartupDiagnostic` describe inner lab startup; outer seat
  lifecycle must only project them into bounded seat status.

### Model mappings, not port offsets

One typed per-instance mapping set must represent participant, recovery, and
host-MCP ingress as `(audience, protocol, outer address, outer port, guest
address, guest port)`. The signed `GuestPublication` remains the allow-list for
fixed guest destinations. The mapping selects an outer endpoint only and must
not modify TechVault, Compose, RAES, or guest service ports.

The canonical projections are `BoundaryEndpoint` for observed mappings and
`SeatEndpoint` for the host-MCP discovery pair. Extend the versioned seat
contract to reference the complete mapping set; do not add unrelated
participant/recovery port fields independently to the CLI, QEMU adapter, kiosk,
state, and access file. Kiosk URLs and client serializers consume the same
validated mapping.

Resolve the namespace boundary explicitly: `GuestPublication`, `SeatEndpoint`
and `sshd_policy()` currently require loopback destinations. An outer QEMU
forwarding declaration does not demonstrate a working path to a guest-loopback
listener. The adapter must prove the approved hop into that namespace, preserve
the restricted dispatcher, and include any forwarding process in boundary
readback. Do not silently substitute a guest NIC/wildcard address or loosen
only one validator. Observe unauthorized listeners owned by the VM as well as
declared mappings; filtering inventory to expected ports can hide exposure.
Inbound mappings also do not prove forbidden guest-to-host or outbound traffic
is blocked; those need the existing boundary enforcement and actual probes.

Explicit pins fail clearly when unavailable. Automatic allocation must be
collision-safe under concurrent launchers. A check-then-close socket probe is
not a reservation. Hold a host-wide allocation lock through selection and QEMU
bind outcome, reject duplicate mappings within one launch, and treat QEMU's
failure to acquire every forwarding endpoint as a failed launch. Re-observe the
listeners and their owning VM before publishing readiness. Preserve mappings on
ordinary restart only after revalidation; reset may allocate replacements and
must increment the generation.

### Bind lifecycle to a VM instance and guest readiness

Fix the invalid QEMU option using documented device syntax and test the emitted
argv with the installed QEMU binary. Keep the fixed argv builder and list-form
subprocess execution. The adapter needs a private management channel, such as a
per-seat QMP Unix socket or an equivalent supervised process handle, so launch
failure, exit, shutdown, and identity can be attributed to this VM. A numeric
PID file and `kill(pid, 0)` are insufficient because of PID reuse. Persist a
bounded process identity or supervisor unit identity and revalidate executable,
start identity, overlay, and management channel before signaling it.

The read-only launch share is public authenticated input, not a secret channel.
Stage `appliance-launch.json`, the contained release, and both public trust
anchors beneath it. The golden must include a systemd mount unit (or equivalent
ordered mount contract) for the QEMU share at `/run/aptl-launch`; first boot must
require the mount before reading those files. Preserve read-only host export and
guest mount semantics, no-follow verification, and signed release validation.
Do not make a writable share or embed trust anchors by copying private build
state into the golden.

Seat readiness requires all of the following for the same generation:

- the tracked QEMU instance is alive and owns the declared outer listeners;
- the guest reports its boot identity, Docker daemon/project identity, admitted
  full-TechVault inventory, inner `LabResult`, and required capture readiness
  over a bounded authenticated management path;
- `run_appliance_boundary_gate()` passes the real host and guest observations,
  including performed positive and forbidden-reachability probes; and
- any enabled restricted SSH transport is enrolled, mapped, and independently
  admitted by `GuestAdmission`.

Never pass `forbidden_reachability_passed=True` by construction. Never mark a
seat ready immediately after `Popen`, from listener inventory alone, or from an
unattributed response on a reused port. Readiness must have a bounded deadline,
observe early QEMU exit, and persist accurate failure or taint state.

### Reuse the canonical build and qualification pipeline

The supported developer/release entry point may orchestrate existing typed
stages, but it must not introduce another payload format or verifier:

- `stage_canonical_inputs()` and `validate_canonical_inputs()` own full
  TechVault wheel, project/build, helper/child-image, and asset-lock closure.
- `build_offline_payload()` owns the deterministic closed outer payload.
- `GoldenImageBuildRequest` and `build_golden_image()` own checksum-verified,
  offline libguestfs construction and clean-golden output.
- release preparation, qualification validation, sealing, launch preparation,
  and `verify_release_directory()` remain the only production trust path.

The missing convenience path should acquire a version-pinned base and packaged
dependencies into an explicit cache, verify them, report build-host tools and
capacity, and then call these incumbents. Downloads occur only during staging.
The guest build and boot remain offline and must fail on attempted package
resolution, image pull, or image build.

Candidate bootstrap is a separate trust mode with visibly development-only
public anchors and output paths. It may enable real boot testing before
production qualification, but cannot emit a production manifest, manufacture
qualification evidence, relax signature checks, or satisfy the independent
machine drill with two seats on one host. Private signing keys and per-user
credentials never enter the golden, payload, repository, CI artifacts, QEMU
argv, or public release.

### Close the APP-3 admission gaps

These are obligations for #1022, not claims that the current verifier or tests
already prove them:

- **Keep qualification acyclic.** `prepare_release_manifest()` already requires
  passing drill and participant reports; production launch requires the sealed
  result. Qualification-only launch therefore needs an explicit development
  trust mode in the existing builder/launcher seam. Authenticate candidate
  content, retain APP-1 enforcement and ordinary input checks, and defer only
  the evidence that the drill itself must produce. Production verification and
  publication must reject that mode. Bind collected evidence to the exact
  candidate disk, payload, profile, policy and source; final sealing must not
  rebuild or modify the tested disk. Do not put the final manifest inside the
  disk it hashes, or bind evidence to its own enclosing manifest digest.
- **Prove provenance, not just syntax.** `ReleaseSource` validates commit syntax
  and tag/version agreement; it does not establish that the installed wheel,
  packaged assets, base, provisioner and scanner came from that commit/build.
  Preserve that relationship through the existing build requests and release
  provenance. `GoldenImageInventory` accepts a clean scanner result, while
  `ApplianceDrillReport` checks distinct IDs and success flags. Neither alone
  proves an independent machine or a scan of these disk bytes. Retain
  authenticated observations tied to the candidate, actual machine identity,
  architecture, resources and supported adapter. Reconcile signed prerequisites
  with the full-TechVault profile and measured minimum-host results; legacy
  guided-profile minima and successful tests on larger hosts are insufficient.
  Extend `scan-golden.sh` rather than treating its current small path list as a
  complete secret scan: base-image accounts, cloud-init state, build logs,
  retained staging archives and bundled image layers can carry control-plane
  credentials too. Apply ADR-029's distinction between intentional vulnerable
  target data and operator secrets. Declaring a hosted adapter in `DeliveryParity`
  is not evidence that the hosted path has been qualified.
- **Repeat content admission at consumption.** The release verifier hashes
  artifacts and checks embedded `inputs.json`, but does not call the complete
  `validate_canonical_inputs()` closure check. New #1022 releases require the
  canonical full-TechVault inputs even though historical release schemas permit
  their absence. Route nested archive, wheel, project and OCI admission through
  `inputs.py`, `payload_content.py` and `input_images.py` before extraction or
  execution; do not merely trust a previous bundle command. Preserve legacy
  compatibility explicitly without allowing downgrade to a legacy payload to
  bypass new-release requirements. The release environment has exactly two
  non-secret fields under `offline._release_environment()`; never accept an
  arbitrary shell file merely because it contains a matching version line.
- **Bound real-size verification.** `verify_artifacts()` currently retains every
  artifact as bytes, and checksum generation rereads them. Reuse streaming
  `utils/deterministic_archive.py` hashing and bounded metadata readers; extend
  the incumbent verifier rather than adding a fast verifier that skips checks.
  Keep verified files stable from hashing through QEMU/libguestfs consumption;
  read-only mode alone does not prevent replacement by a directory owner.
  Bound metadata, member counts, expansion and temporary disk use. Account for
  sparse disk size, expanded filesystems, OCI import and concurrent overlays,
  rather than sizing admission from compressed downloads alone.
- **Validate every parser boundary.** Closed Pydantic fields and duplicate
  artifact checks do not themselves reject duplicate JSON object keys. Require
  unambiguous release/signature/evidence decoding before canonicalization, and
  reject artifact paths colliding with reserved manifest/signature/checksum
  names. Revalidate externally derived updates; `model_copy(update=...)` is not
  a validation gate. No-follow containment must cover ancestor directories as well as the
  leaf. Fixed subprocess argv prevents shell parsing but not QEMU's comma-based
  option parsing: paths embedded in `-drive`/`-fsdev` need an admitted encoding
  or rejection rule. Admit standalone qcow2 bases with no unapproved external
  backing/data references before virtualization tools open them; only the
  launcher-created overlay may reference the verified golden.
- **Validate the guest target.** Canonical input validation currently compares
  the exact Python version and architecture of the running interpreter, and
  wheel/OCI checks use that environment. Stage and validate for the declared
  guest target, not whichever Python happens to run on the build host. Any
  future cross-build support belongs in this target-validation seam. The base
  must contain rootful Docker, Node and all guest runtime tools, an
  offline-compatible Python environment, and enough partition/filesystem space;
  `qemu-img resize` alone does not grow the guest filesystem. Verify executable
  modes, systemd mount ordering/sandbox permissions and interrupted-first-boot
  recovery in a real guest. Do not install packages at first boot to mask gaps.
- **Authenticate observations separately from content hashes.**
  `observation_id_for()` identifies content; it is not a signature or proof of
  origin. A read-only share also does not authenticate whoever selected its
  trust anchors. Carry independently provisioned anchors and authenticated,
  generation-bound observations over the launcher management boundary. Both
  host and guest observations currently compare `boot_id` against one binding;
  reconcile the outer-host boot identity and guest boot identity explicitly
  rather than copying one into the other. A create-once descriptor must not
  hash a future readiness observation: stage launch intent separately from
  fresh observed readiness in the incumbent launch/observation contracts.
- **Preserve multi-user ownership.** A shared verified golden/cache can be
  read-only, but each overlay, grant, management socket and access record needs
  its own owner and generation. Mode `0600` is not proof of the expected UID.
  Reuse `lifecycle_guard.py`, `pathsafe.py`, guest-management ownership checks
  and atomic seat persistence for locking and validation. The host-wide port
  reservation must coordinate different Unix users; separate per-user locks
  cannot reserve the same host socket. Do not solve this with world-writable
  state or a new general-purpose privileged daemon. Shared cache layout must
  respect `prepare_launch_descriptor()`'s contained release and no-follow
  contract; a symlink to another user's release is not an admissible shortcut.

The focused release, payload, canonical-input roundtrip, guest-asset and seat
tests are the regression owners. Add adversarial admission coverage there,
including correctly signed but internally inconsistent candidates; signature
tampering tests alone miss validator gaps. Real KVM, offline boot and
independent-machine evidence remain distinct acceptance results.

### Keep publication outside appliance identity

GitHub Releases are the public index for qualified appliance versions; GHCR is
only for project-owned OCI images. A qcow2 disk and Docker/OCI image remain
different artifact kinds. The existing signed appliance manifest and
qualification signatures remain the canonical content identity regardless of
compression or transport chunking.

Extend the existing release workflow rather than creating an unrelated
publisher. Publication must consume already qualified, sealed bytes from the
exact tagged commit, use pinned actions and minimal job permissions, and never
publish a candidate. Verify project-owned GHCR package visibility with an
anonymous pull. Verify third-party redistribution rights and notices before
bundling; a digest pin does not grant redistribution rights.

If a canonical artifact exceeds the current per-asset limit, use one versioned
distribution index that references the signed manifest digest, canonical file
digest and size, compression parameters, and ordered chunk digests. Authenticate
that index with the release's approved publication/provenance mechanism. The
downloader verifies the index before reconstruction, reconstructs automatically,
then verifies the canonical artifact and the existing appliance signatures.
Chunking must not create a second appliance identity or require manual joining.
The index must not authenticate itself with a key downloaded beside it. Reuse
the configured release trust or explicitly verified publication provenance;
bound redirects, download sizes and reconstruction paths. Publish complete
immutable assets before making a version discoverable. An interrupted upload
cannot become an admissible release, and retries cannot use `--clobber` to
replace different sealed bytes. OIDC build provenance does not replace either
the Ed25519 release signature or the qualification attestation.

The staging client should be retry-safe and resumable, use a content-addressed
cache, preflight compressed and expanded disk space, use no-follow/atomic
publication, and admit only a fully reconstructed verified release. Version
selection is explicit. Anonymous download, verification, stage, boot, and reset
are release acceptance, not documentation-only checks. Current GitHub limits
and anonymous GHCR behavior must be checked when the workflow is implemented;
do not freeze a web-service limit into the signed appliance schema.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Scenario and packaged inputs | `resolve_scenario_bundle()`, `ScenarioBundle`/`PackIdentity`, `src/aptl/appliance/{inputs,input_profile,input_images,payload_content,offline}.py`, `hatch_build.py`, `_asset_manifest.py`, npm lockfiles, and `mcp/build-all-mcps.sh`. Do not invent an appliance scenario, image list, asset lock, or dependency resolver. |
| Release trust and overlays | `appliance/{models,release_models,manifest,release_validation,launch,build,bootstrap}.py` and `utils/deterministic_archive.py`. Reuse strict Pydantic models, RFC 8785 bytes, lowercase SHA-256 identities, Ed25519 verification, safe relative paths, create-once outputs, and read-only golden backing files. |
| Boundary admission | `core/appliance_boundary.py`, `appliance_boundary_inventory.py`, `appliance_boundary_gate.py`, and the deployment boundary compiler/readback. Extend trusted guest-to-outer mapping support; never weaken listener equality, default-deny enforcement, Docker-authority inspection, or negative probes globally. |
| Port semantics | `core/host_ports.py`, `_port_bindings.py`, and `endpoints.py` already distinguish host publication from target port and report resolved endpoints. Reuse that vocabulary and parsing/reporting behavior. Its Compose allocator is not a seat reservation primitive because it closes probe sockets and exports environment overrides; do not call it as though it solved concurrent QEMU allocation. |
| Seat lifecycle and persistence | `appliance/seat/{models,context,paths,persistence,prereqs,vm,observation,exposure,lifecycle}.py` and `cli/seat.py`. Evolve the versioned contract and the one lifecycle adapter; do not create a second state machine, state file, exception hierarchy, or launcher script. |
| Guest startup and diagnostics | `appliance/guest/`, `core/lab.py`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, and ADR-030. Guest readiness reports typed, redacted state; the host does not parse arbitrary journal or Docker output. |
| Host MCP access | `workbench/{access,preparation,guest_binding,dispatch,access_clients,client_files,process}.py`, `cli/mcp_access.py`, and `docs/reference/host-mcp-access.md`. Reuse `SeatAccessRecord`, `CallerGrant`, forced-command SSH, role profiles, per-call guest admission, bounded processes, and native client serializers. |
| Runtime ownership | `DeploymentBackend`, `_docker_endpoint_binding.py`, receipt-backed full container inspection, lifecycle observation locks, capture authorities, and run/session identity. Discovery must use full native container IDs and the selected guest daemon/project. |
| Safe I/O, errors, and observability | `utils/pathsafe.py`, `_atomic_write`, `seat/persistence.py`, `SeatLauncherError`, boundary finding codes, `get_logger()`, `redact()`, and the TypeScript redactor parity contract. Persist owner-only through no-follow atomic writes and expose bounded stable codes, identities, counts, timings, and verdicts only. |
| Release automation | `.github/workflows/release-please.yml`, pinned-action conventions in `.github/workflows/`, existing PyPI OIDC/provenance/SBOM publication, `docs/releasing.md`, and package/version tests. Add appliance qualification/publication as a gated extension, not an alternate tag or release process. |

## Security And Validation Passage

The intended design must pass every layer below.

| Layer | Required passage |
| --- | --- |
| Source and supply chain | Resolve an exact tag/full commit, hashed Python and npm locks, immutable OCI identities, verified base-image bytes, complete helper/child-image closure, and redistribution review. Scanners and SBOMs supplement, but do not replace, signed content identity and real qualification. |
| Release shape and signatures | Parse only the closed appliance models; reject unknown versions/fields, unsafe paths, duplicates, digest/size mismatch, missing canonical inputs, invalid qualification signatures, or inconsistent machine drills before creating an overlay. Development trust cannot validate production output. |
| Archive and filesystem | Reuse bounded archive-member validation, no links/special files/traversal/duplicates, expansion limits, no-follow opens, contained paths, owner-only directories, atomic replacement, and correct modes. Download cache content is untrusted until reconstructed and verified. |
| Configuration and environment | Keep scenario/runtime settings in strict `AptlConfig`, `load_dotenv()`/`EnvVars`, placeholder validation, and declared realization outputs. Outer mappings belong to the seat contract, not `aptl.json`, `.env`, Compose rewrites, or a flat environment bag. |
| MCP environment and config shape | Reuse `GuestAdmission._service_environment()`, lab MCP configuration sync, workbench profile/credential aliases and `mcp/aptl-mcp-common/src/config.ts`. Pass only declared guest service leases and validated guest port values, with `APTL_MCP_DISABLE_DOTENV=1`; never inherit host provider auth, host Docker selection or arbitrary SSH environment. Preserve common endpoint URL, TLS/CA and SSH host-key checks. |
| Authentication and authorization | Recovery remains instructor-only. Host MCP uses the dedicated public-key account, restricted key, fixed dispatcher, `CallerGrant`, role profile, current generation, per-call guest identity/capture checks, and revocation. The access file, endpoint possession, seat name, and SSH username grant no authority. |
| Browser and operator auth | Preserve workbench `ParticipantAuthorizer` and role-scoped routes. `api/deps.py` owns operator bearer and WebSocket authentication; do not publish that operator API as participant ingress or turn readiness into an unauthenticated management API. Use existing native client serializers and owner-checked managed-file updates for host client configuration. |
| Secret handling | Provider authentication stays with each user's host client. Transport private keys, bootstrap credentials, service leases, session material, and release private keys are absent from images, snapshots, discovery, URLs, argv, environment dumps, unit files, logs, CI artifacts, and public assets. Public trust anchors and host public keys are not secrets but remain identity-bound. |
| Endpoint, TLS, and SSH | Validate each outer-to-guest mapping against the signed guest publication. Preserve pinned SSH host keys, fixed SSH argv, `-F /dev/null`, no agent/multiplexing/forwarding/PTY/environment, and existing TLS/CA endpoint validation. Never expose guest Docker or an outer `DOCKER_HOST`. |
| OS and hypervisor | Validate effective KVM read/write permission for the invoking user, QEMU feature support, architecture, available rather than total RAM/disk/CPU capacity, and per-seat resource reservations. Nested KVM is diagnosed only when the host itself is virtualized. Shares stay read-only; no host Docker socket, generic guest shell, clipboard, USB, or writable host mount is added. |
| Boundary and readiness | Bind release, boot, daemon, process, mapping, policy, RAES plan, enforcement readback, probes, and capture to one fresh observation. Run the complete boundary gate. A listener, HTTP 200, systemd active state, or fabricated boolean is not readiness. |
| Persistence and invalidation | Version `SeatRecord` and `SeatAccessRecord` independently. State transitions publish atomically under a mutation lock. Stop/failure/reboot invalidates discovery freshness; reset/replacement revokes grants and changes generation and pins before new access is published. Stale evidence never becomes current through timestamp refresh alone. |
| Error and telemetry envelopes | Public CLI/status returns stable `SeatLauncherError` or boundary codes and coarse redacted state. Private diagnostics may retain bounded QEMU/guest failure details with owner-only access and retention, but must pass `redact()` before any support, log, telemetry, or CLI boundary. Never emit raw stderr, environment, policy documents, host paths, Docker inspect, keys, or evidence bytes. |

Translate `ApplianceManifestError`, `ApplianceBuildError`, `OfflinePayloadError`
and `WorkbenchConfigurationError` at their existing CLI/lifecycle boundaries;
do not create a common replacement exception tree or print Pydantic input
values. Redact before diagnostic persistence as well as publication; private
file permissions are not a redaction boundary. Reuse `get_logger()`, OTel,
`LabResult`/`StartupDiagnostic`, runstore and Python/TypeScript redactor parity.
Best-effort telemetry failure must not masquerade as failed authorization, and
mandatory capture/boundary failure must not become advisory telemetry.

## Extensibility And Whole-Repository Scope

The required seam is a versioned **seat launch binding** composed from existing
types: seat/instance/generation identity, verified launch descriptor digest,
overlay reference, VM process identity, resource reservation, and a collection
of typed outer-to-guest mappings. QEMU/KVM is the first adapter. A future
libvirt/hosted adapter, IPv6 loopback mapping, or additional approved audience
adds adapter behavior or another mapping entry without changing TechVault,
`GuestPublication`, client config schemas, or lifecycle vocabulary.

Distribution has a separate transport seam: canonical release identity plus an
optional authenticated reconstruction index. A future large-object store or
mirror changes transport locations only; the reconstructed release still passes
`verify_release_directory()` unchanged.

Repository-wide reconciliation includes:

- `src/aptl/appliance/`, `src/aptl/appliance/seat/`, `src/aptl/cli/{appliance,seat,mcp_access}.py`, and `appliance/guest/`;
- `src/aptl/core/appliance_boundary*.py`, config/env/endpoints/host-ports,
  lifecycle guards, deployment ownership, runstore, capture, and telemetry;
- `src/aptl/workbench/` access, dispatcher, process, profiles, browser, and
  client-file surfaces;
- full-TechVault Compose/container/config assets, image helpers, Python/npm
  locks, package asset manifests, and participant qualification models;
- appliance, boundary, seat, MCP, guest-asset, installed-artifact, negative,
  and real KVM integration tests;
- `.github/workflows/`, release/provenance/SBOM conventions, `.ground-control.yaml`
  path routing, and release/seat/host-access documentation; and
- host QEMU/KVM, `/dev/kvm` permissions, systemd/supervisor state, loopback
  sockets, filesystem capacity, nested-virtualization diagnostics, GHCR, and
  GitHub Release transport.

Current `.ground-control.yaml` boundary paths omit `src/aptl/appliance/**`,
`src/aptl/workbench/**` and `appliance/guest/**`. Reconcile these with the
existing host, perimeter and control-plane boundary owners during implementation;
do not claim the present routing already covers the new delivery path.

## Gotchas And Anti-Patterns

- Do not conflate guest ports with outer ports, a port offset with a mapping,
  or a listening socket with ownership by the selected VM.
- Do not conflate a golden qcow2, OCI image, offline payload, overlay, release
  manifest, qualification report, access record, or transport chunk under a
  generic artifact schema.
- Do not create parallel endpoint, access, release, observation, readiness,
  lifecycle, validation, or exception models. Version the incumbent owner when
  its contract truly changes and update every reader, writer, fixture, digest,
  and signature binding.
- Do not reject an unrelated responding host Docker daemon. Prove that the
  launcher and guest use no host Docker authority and inspect only resources in
  the seat's authority boundary.
- Do not probe all loopback listeners as though they belong to the seat. Observe
  the declared mappings and owning process; unrelated matching listeners are a
  conflict or unrelated workload, never readiness evidence.
- Do not reuse a PID after reboot, signal an unverified PID, overwrite an
  immutable launch descriptor, carry a completed observation across reset, or
  refresh a stale access file without re-observing the guest.
- Do not put secrets in QEMU/SSH command lines, cloud-init/user data, release
  URLs, browser storage, generated client config, discovery, or CI logs.
- Do not make the host launcher a Docker proxy, guest shell, raw-log API,
  evidence browser, package resolver, or second APTL control plane.
- Do not claim real-VM evidence from mocked `Popen`, argv tuple assertions,
  script-text inspection, synthetic boundary observations, or two overlays on
  one physical machine.
- Do not publish an unqualified candidate, mutate prior release assets in
  place, overwrite rollback releases, rely on authenticated GitHub access for
  the public path, or assume a public repository makes GHCR packages public.
- Do not document `docker pull` for qcow2 disks or let transport compression and
  chunks alter the signed canonical disk/payload identity.

## Non-Goals And Implementation Boundary

- This preflight does not implement the builder, downloader, QEMU adapter,
  guest health channel, allocator, access publisher, KVM runner, or CI release.
- It does not redesign TechVault topology, RAES SDL, Compose service ports,
  `DeploymentBackend`, participant roles, MCP tools, browser routes, capture,
  evidence, or operator API contracts.
- It does not make rootless Docker part of this issue; #1053 remains
  independent. Rootful Docker stays inside each guest.
- It does not permit shared guest Docker, shared mutable overlays, in-place
  golden upgrades, snapshot rollback as reset, host-side provider credential
  management, host Docker socket mounts, or general participant SSH.
- It does not weaken production qualification for developer convenience or
  replace the required independent-machine drills with CI emulation.
- It does not authorize publication by itself. Only already qualified and
  sealed release bytes may enter the public workflow.
