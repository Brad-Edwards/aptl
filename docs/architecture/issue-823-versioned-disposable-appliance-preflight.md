# Issue #823 Versioned Disposable Lab Appliance Preflight

This note sets the design guardrails for the versioned participant appliance.
It is guidance, not an implementation plan. [ADR-049](../adrs/adr-049-sealed-disposable-lab-appliance.md)
already makes one disposable VM per seat the supported delivery boundary.
Issue #820 owns the bounded inner workload, issue #821 owns its workbench
compartments, and issue #822 owns its appliance network boundary. Issue #823
binds and qualifies those existing contracts; it does not replace them.

No new ADR is needed. The unresolved risk is treating an image file, a Docker
cache, and a participant seat as the same artifact. They have different
owners, mutability, integrity, and reset semantics.

## Architecture Decisions And Guardrails

- The local reference form is a hardware-virtualized QEMU/KVM guest managed by
  a narrow launcher adapter. The hosted fallback consumes the exact same signed
  guest payload and exposes the same participant routes and workbench flow.
  A host adapter is an outer delivery concern, not an APTL
  `DeploymentBackend`, a RAES node provider, or a reason to select another
  Compose file, scenario, MCP set, frontend build, or credential meaning.
- The release unit is a signed, versioned appliance envelope. Its narrow,
  strict payload manifest binds the tagged source revision and APTL version to
  the immutable golden disk, guest OS/architecture, staged payload contents,
  participant-profile manifest and asset-lock digests, accepted qualification
  report, appliance-boundary policy/binding, helper-image digests, and declared
  host prerequisites. It contains references and digests, not a second copy of
  RAES topology, `AptlConfig`, MCP configuration, readiness checks, or egress
  rules.
- Manifest validation occurs before launch and produces the existing
  `ApplianceBoundaryBinding` payload digest for
  `run_appliance_boundary_gate()`. The boundary inventory is the readiness
  projection for the payload digest; it may add the non-secret release version
  and manifest digest, but it must not become a second payload manifest or a
  new readiness taxonomy. The signed manifest is the canonical source for
  `aptl` version reporting, artifact checksums, and rollback eligibility.
- A build from the same annotated APTL tag must produce the same **release
  shape**: the same manifest identity, guest OS/base digest, profile and policy
  bindings, package/image/MCP content identities, file ownership contract, and
  launch contract. It need not produce byte-identical disk images, timestamps,
  filesystem UUIDs, generated keys, Docker object IDs, or qualification run
  records. Build provenance must record the resolved immutable commit, not only
  a mutable tag name.
- Use the existing staged asset closure. `ParticipantProfileManifest`,
  `ParticipantAssetLock`, `load_participant_profile()`, and
  `hatch_build.py`/`aptl.core.assets` already define how tracked APTL assets,
  MCP builds, and OCI identities are selected without shipping ignored local
  state. The outer payload adds the guest-base and launcher artifacts that the
  inner lock intentionally does not own; it must not reimplement asset-lock
  validation or copy its entries into another schema.
- The golden disk is immutable/read-only once released. It contains the
  supported guest OS, installed APTL release, staged project assets, released
  MCP builds, verified OCI content, appliance policy, and non-secret workbench
  material. It contains no participant data, `.env` values, generated keys or
  certificates, `.aptl` session/run state, Docker runtime state, model or
  operator credentials, or prior qualification evidence with sensitive data.
- One launch creates one disposable overlay and all associated mutable guest
  state on it. That includes the guest machine identity, SSH/TLS host identity,
  generated service configuration, Docker writable state and volumes, session
  credentials, run/evidence state, and any writable firmware/seed state. No
  host shared folder, host Docker socket, guest-root mount, clipboard,
  drag-and-drop, USB, or writable device passthrough is an allowed substitute
  for that overlay.
- First boot is a deterministic, idempotent state transition, not deterministic
  secret bytes. It must atomically establish a new instance identity and
  credentials exactly once per overlay, recover safely after an interrupted
  boot, and never regenerate them on an ordinary reboot. Entropy-generated
  values are deliberately different for each overlay and are destroyed with it.
  A local credential entry and hosted short-lived credential injection both
  resolve to the same guest-only bootstrap shape from ADR-049.
- Offline staging is an appliance property. A fresh overlay may start services
  and generate per-seat state, but it must not require a source checkout,
  package installation, image pull/build, MCP build, DNS fallback, or arbitrary
  network download. The guest base and every OCI/MCP/package input required by
  the bounded profile must be verified and present before the release becomes
  eligible. A build-time network fetch is acceptable only through a pinned,
  checksummed staging input and must not become a first-boot dependency.
- Rollback and upgrade select an immutable signed payload; neither mutates a
  golden disk in place. The launcher keeps an atomic active/previous
  known-good payload reference after verification. Rollback discards the
  candidate overlay and creates a fresh overlay from the prior payload. Upgrade
  creates a fresh overlay from the new payload and reruns the same start gate.
  Migrating a whole guest disk, Docker volume, secret store, or compromised
  overlay is not an upgrade. Any future explicit data import needs its own
  versioned, validated, classified contract.
- The appliance manifest declares real host prerequisites, rather than reusing
  developer-from-source prerequisites. It must state architecture, usable CPU
  count, host memory and disk including virtualization overhead, hardware
  virtualization and KVM availability, supported hypervisor/launcher versions,
  and required network/device isolation. The current `guided-purple` inner
  profile establishes a lower bound of x86-64, 8 vCPUs, 16 GiB, and 100 GiB;
  the appliance launcher must declare and prove any additional host headroom
  rather than silently oversubscribing that fixture.

## Existing Contracts To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Outer boundary | ADR-049 and its versioned appliance-envelope seam own payload identity, delivery form, host recovery, secret bootstrap, egress-policy reference, resource limits, and evidence export. `ApplianceBoundaryBinding`, `run_appliance_boundary_gate()`, and the fatal boundary inventory consume the payload identity. |
| Bounded workload | `ParticipantProfileManifest`, `ParticipantAssetLock`, `ParticipantReadinessSuite`, `load_participant_profile()`, and `evaluate_participant_qualification()` own the inner profile, exact surfaces, offline counters, resource ceilings, and authenticated qualification evidence. |
| Smoke workflow | `run_participant_mcp_smoke()` and the profile readiness suite own the real red-to-blue semantic workflow. A process start, a container health check, or a copied status flag is not a smoke result. |
| Scenario and realization | RAES parsing/planning, `AptlRealization`, `DeploymentRealizationSpec`, `DeploymentBackend`, and the APP-1 boundary policy retain their existing ownership. The outer VM must not create a VM node backend, a second ACL model, or an appliance-specific scenario. |
| Buildable source assets | `hatch_build.py`, `aptl._asset_manifest`, and `aptl.core.assets` own tracked-source selection and exclusion of generated state. Build/package tests already protect against shipping `.aptl`, keys, certificates, or local `.env` state. |
| Durable configuration | `AptlConfig`, `load_config()`, and ADR-025 remain the strict non-secret configuration contract. Envelope policy, release identity, and bootstrap material are not an `aptl.json` dictionary or environment-variable bag. |
| Secrets and generated files | `load_dotenv()`, `EnvVars`, placeholder checks, ADR-028 containment/atomic writes, ADR-029 redaction, `curl_safe`, and owner-only ignored generated state remain mandatory. Use the ADR-049 narrow bootstrap parser for new seat secrets. |
| Lifecycle and errors | `core.lab`'s flat `_LAB_START_STEPS`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, deployment timeouts, and RAES `Diagnostic` remain the inner lifecycle vocabulary. Outer seat lifecycle and taint are distinct envelope state; do not create an appliance-wide exception hierarchy. |
| Persistence and observability | `RunStorageBackend`, `LocalRunStore`, `RangeSnapshot.to_dict()`, evidence/capture contracts, `get_logger()`, OTel, and the Python/TypeScript `redact()` helpers remain the only persistence and logging boundaries. |
| Version and release provenance | `aptl.__version__`, `pyproject.toml`, `tests/test_version_consistency.py`, release-please, and the existing Ed25519 qualification-attestation pattern are the canonical version, release, and signature precedents. The payload signer must use an independently configured release trust anchor, never a key supplied by the artifact being verified. |

## Security And Validation Passage

The intended design crosses each of the following gates. Passing a lower layer
does not waive an earlier or later one.

| Layer | Required behavior |
| --- | --- |
| Release manifest and artifact parser | Use one closed, versioned manifest shape with safe relative references, exact lowercase digests, duplicate rejection, existing `rfc8785` canonical JSON bytes, and signature verification against a configured release trust anchor. Unknown schema/version, unresolved tag/commit, missing stage input, digest/signature mismatch, or an unsupported guest/adapter capability fails before an overlay is created. |
| Profile, asset, and qualification validators | Reload the existing strict participant profile and asset lock; verify the accepted qualification report with its protected Ed25519 public key. The payload manifest binds their digests and does not accept handwritten service lists, scenario paths, or MCP inventory. |
| Appliance boundary policy and host observation | Bind the verified payload digest into `ApplianceBoundaryBinding`; pass the signed APP-1 policy and a fresh authenticated host observation to `run_appliance_boundary_gate()` at image qualification and every supported start. Missing/stale host observation, boot/daemon mismatch, extra listener, incomplete readback, or failed positive/negative probe is fatal, not `degraded_*`. |
| First-party configuration and environment | Keep durable non-secret settings in strict `AptlConfig`. Existing `.env` values pass through `load_dotenv()`, `EnvVars`, and placeholder checks; generated service files retain no-follow, containment, atomic-write, and restrictive-mode handling. The envelope never bypasses those parsers or passes opaque settings through to Compose. |
| Credential bootstrap and OS/process exposure | Generate or inject seat credentials only after overlay creation into management-owned guest state. Do not place a secret in the golden image, cloud-init/user-data log, process argv, environment dump, URL, browser storage, Compose command/healthcheck, image label, support bundle, or host state. Preserve argv-list subprocess construction and avoid generic guest shell or Docker APIs. |
| Docker, network, and virtual-machine authority | Keep Docker/Compose and MCPs inside the guest and retain guest-Docker authority with the smallest existing management owner. The QEMU/libvirt adapter exposes only declared participant and recovery endpoints, uses no shared host resources, and validates VM/CPU virtualization prerequisites before launch. The APP-1 observed boundary, not a `qcow2` extension, loopback bind, `internal` Docker network, or successful TCP check, proves containment. |
| Errors, logs, and reports | Report stable release/validation/finding codes, APTL version, payload/manifest/policy digests, counts, timing, resource pressure, and verdicts only. Reuse `LabResult`/`StartupDiagnostic`, boundary findings, and redacting writers; never return raw QEMU/libvirt output, Docker inspect, host paths, policy text, secrets, or evidence bytes. |
| Evidence and reset | Keep run/capture state guest-management-owned and classified under the existing runstore/evidence contracts. A normal host report contains only redacted identity and coarse readiness. Destroying an overlay removes all unexported participant state; a deliberately approved, checksummed export is the only exception. |

## Extensibility And Whole-Repository Scope

The seam is ADR-049's one versioned appliance-envelope contract: immutable
payload identity, delivery-form adapter, participant ingress, health/recovery
adapter, secret-bootstrap channel, egress-policy reference, resource limits,
and evidence-export sink. The payload manifest is its release projection. A
future hosted provider, local hypervisor, supported guest architecture, update
mirror, or recovery adapter adds a declared capability at this seam and uses
the same verifier. It must not fork the scenario, Compose model, frontend,
participant profile, MCP configuration, readiness suite, or error envelope.

Implementation has to reconcile all of these surfaces, not only the appliance
builder:

- `pyproject.toml`, `uv.lock`, `hatch_build.py`, `release-please-config.json`,
  `.github/workflows/release-please.yml`, and package/version/asset tests;
- `participant-profiles/guided-purple-v1/`, its profile/asset/readiness
  validators, qualification evidence, semantic MCP smoke, and minimum-hardware
  fixture;
- `src/aptl/core/appliance_boundary*.py`, APP-1 policy/binding, boundary
  helper/proxy images, guest/host observations, and their static/live tests;
- `src/aptl/core/{assets,config,env,lab,lab_types,runstore,telemetry}.py`,
  deployment backend behavior, generated-state writers, host-port and endpoint
  projections, and the RAES realization pipeline;
- `docker-compose.yml`, profile-derived runtime, Docker image/mount/capability
  policy, MCP build artifacts/configuration, participant workbench, container
  Dockerfiles, and guest Docker daemon state;
- physical QEMU/KVM/libvirt guest lifecycle, CPU virtualization, overlay and
  firmware state, virtual device policy, host listener/reachability observation,
  and a hosted adapter with the same payload digest;
- `.ground-control.yaml` boundary declarations, deployment/workshop/recovery
  documentation, asset/package security tests, appliance/profile/boundary
  tests, and the repository completion gates. New appliance-builder or launcher
  paths must be declared under the appropriate outer host/perimeter boundary
  rather than left outside GRC routing.

## Verification Guardrails

- Qualification must verify the signed payload and every staged checksum,
  demonstrate that the golden base contains no per-seat identity, secret,
  Docker writable state, run data, or host share, and prove a fresh overlay
  creates distinct identity and credentials without a source checkout or a
  network resolution.
- The complete existing `guided-purple` readiness suite, including the semantic
  red attack, Wazuh detection, indexer/Wazuh investigation, participant
  workbench surface, correlation record, and APP-1 positive/negative boundary
  probes, must run on the declared minimum appliance host. Existing profile
  and boundary reports remain distinct but are bound by the same payload
  digest.
- Exercise build, launch, artifact verification, rollback to the immediately
  previous known-good payload, and overlay destruction on more than one
  independent supported machine. Verify that a failed candidate cannot replace
  the active known-good reference and that rollback creates a clean prior
  overlay rather than reviving candidate state.
- Static tests should reject manifest tampering, wrong tags/commits, unsafe
  paths, unknown schema fields, duplicate entries, unsigned/incorrectly signed
  manifests, missing staged inputs, unsupported virtualization, golden secret
  contamination, and stale version projection. Integration/live evidence must
  cover actual KVM launch, offline boot, reset, host exposure, and bounded
  workflow completion; mocked QEMU output is not sufficient evidence.
- Any Compose, container, or configuration change still requires the existing
  clean-lab validation, focused pytest/vitest coverage, and `pre-commit run
  --all-files`. Changes to `aptl-mcp-common` still rebuild every dependent MCP.

## Gotchas And Anti-Patterns

- Do not call the wheel, asset lock, OCI cache, golden disk, per-seat overlay,
  run archive, qualification report, and hosted image one generic "artifact."
- Do not use an unpinned package repository, mutable OCI tag, mutable Git tag,
  local build cache, or post-build image pull as release input.
- Do not bake `.env`, generated certificates/keys, machine IDs, host keys,
  session tokens, model credentials, Docker volumes, `.aptl`, run archives, or
  a copied participant overlay into the golden payload.
- Do not use snapshot rollback, `aptl lab stop -v`, RAES episode reset, or a
  container restart as the appliance reset/rollback contract. Do not repair a
  participant guest in place and then return it to a seat.
- Do not put an appliance policy, host prerequisite, or manifest field in
  `aptl.json`, an environment variable, Docker label, or a new duplicate
  profile/readiness/ACL schema merely because it is convenient for one
  launcher.
- Do not let the hosted fallback rebuild, reconfigure, or present a different
  UX than the local payload. Provider-specific metadata cannot override the
  signed payload identity or guest-side credential lifecycle.
- Do not turn the outer launcher into a participant shell, Docker proxy,
  arbitrary port tunnel, raw-log/evidence browser, or generic file API.
- Do not treat successful disk creation or a container health check as payload,
  boundary, readiness, or smoke proof. Each has separate observable evidence.

## Non-Goals And Implementation Boundary

- This preflight does not implement the guest image builder, signer, KVM
  launcher, hosted fleet, secret-bootstrap transport, kiosk, or rollback tool.
- It does not change RAES SDL, scenario meaning, node-realization semantics,
  `DeploymentBackend`, `AptlConfig`, participant/runtime DTOs, existing MCP
  tool schemas, run/evidence schemas, or the operator control plane.
- It does not add a second package manager, image registry, Docker authority
  broker, readiness engine, exception hierarchy, lifecycle state machine,
  secret store, participant profile, or hosted-only source fork.
- It does not promise byte-identical disks, identical randomly generated
  identities, multi-seat sharing, in-place upgrade, guest preservation after
  compromise, general Kali/target egress, or a proof that guest escape is
  impossible.
