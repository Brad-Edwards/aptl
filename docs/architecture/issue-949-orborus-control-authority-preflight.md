# Issue #949 Orborus Control Authority Preflight

This note fixes the repository-wide boundaries for realizing an authored
runtime orchestration authority and preparing its spawned-image closure. It is
architecture guidance, not an implementation plan. The issue contract and the
portable RAES model remain authoritative; APTL must not infer Shuffle policy
from a seed script, a live Docker cache, or product names.

This note also narrows ADR-049's blanket prohibition on scenario-workload
Docker sockets. A selected node may receive the guest Docker socket only when
the admitted RAES plan gives that same node an exact, read-write Docker
`RuntimeControlInterface` referenced by a host-root-equivalent
`RuntimeOrchestrationAuthority`. Every other raw-socket prohibition in ADR-049
continues to apply.

## Architecture Decisions

- Preserve the existing authority chain:
  authored pack -> RAES parse/semantic validation/compile/plan ->
  `interpret_provisioning_plan()` -> immutable deployment realization ->
  `DeploymentBackend` -> effective Compose model and observed runtime. Keep
  the RAES `RuntimeConfiguration` on its node; do not mirror its portable
  interface, authority, lifecycle, or spawn-template models in APTL. The RAES
  boundary instead emits one backend-neutral admission DTO containing the
  already-decided endpoint, privilege, child provenance/count/label/deadline,
  and admitted mount footprint that core deployment code consumes directly.
- Resolve `control_interface_ref` only within the authority's node. RAES owns
  the portable reference and semantic validation. The APTL Docker adapter
  independently requires one unambiguous same-node match and fails closed if
  it cannot realize the admitted combination.
- Compute Docker-authority admission once from the complete deployment graph
  and carry that typed decision into every lowering and observation stage. An
  authority holder must be a service-backed `soc` management node with no
  participant service, published port, or joined network namespace. This
  classification comes from the resolved backend interaction graph rather
  than the node's runtime authority payload. A node's self-authored authority
  is necessary but never sufficient to grant the socket; absent, stale, or
  participant-serving admissions fail closed. Core deployment modules do not
  import RAES adapters or recompute this policy from the retained runtime.
- Treat control-interface lowering as a closed backend capability, not generic
  mount lowering. The initially supported tuple is Docker engine, Unix socket,
  read-write access, host-root-equivalent privilege, and the exact guest-local
  source and target `/var/run/docker.sock`. Unknown protocol values, arbitrary
  host paths, TCP endpoints, named pipes, cross-node references, duplicate
  targets, and weaker or broader privilege encodings are unsupported.
- Bind the local backend to the selected endpoint before any artifact
  availability probe. Do not inherit `DOCKER_HOST` or a Docker context. Every
  availability, pull, inspect, Compose-config, start, and runtime-observation
  operation must address that same endpoint and corroborated daemon identity.
- Validate the socket with `lstat`, connection/daemon inspection, and bounded
  operations. Record the socket device/inode/type and daemon ID, then recheck
  immediately before image preparation and before service startup. Missing,
  inaccessible, non-socket, symlink-substituted, replaced, or differently
  identified endpoints are fatal. A path string alone is not daemon identity,
  and APTL must not change ownership or permissions to make the check pass.
- Lower exactly one long-form read-write bind into only the authority-holding
  service. Validate its source, target, type, access, and cardinality against
  the effective generated Compose JSON before startup. Also reject effective
  `DOCKER_HOST`/`DOCKER_CONTEXT` values, including image defaults, that could
  direct Orborus elsewhere. Do not add the socket to static Compose as a
  fallback and do not propagate it to worker/app containers. The same shared
  capability predicate rejects a host bind whose source is the socket, an
  ancestor containing it (including `/` or `/var/run`), or a resolved alias
  such as `/run/docker.sock`, even when that broader target was declared.
- Derive the child-image closure only from every admitted authority's typed
  `spawn_templates`. Each `image_ref` must be a canonical digest-qualified
  reference. Deduplicate exact references for work while retaining node,
  authority, and template provenance for diagnostics. An unsupported selected
  authority or malformed/mutable child identity is fatal rather than ignored.
- Require each spawn template to have one matching typed `realized_children`
  record joined one-to-one by exact image, with a distinct stable workload
  identity, a positive expected count, and a unique stable
  `docker-label:key=value` correlation selector. Duplicate-image templates are
  ambiguous under the portable model and therefore fail closed.
  Runtime observation intersects that selector with the exact image filter;
  daemon-wide image scans, timestamps, and container-name guesses are not
  ownership evidence. Because Docker's `ancestor=` filter includes descendant
  images, every selected child is inspected and its immutable image ID must
  equal the daemon-local ID of the exact authored repo digest. Final post-work
  attestation requires the exact authored count, so auto-removal cannot turn
  missing evidence into vacuous success.
- Keep spawned-image requirements distinct from
  `DeploymentImageRealization`. That existing type selects a node service's
  image and writes a Compose override; a spawned child is neither a node nor a
  Compose service. The deployment realization already carries typed node
  runtimes, so image preparation can consume the derived closure without a
  second serialized plan or fake services.
- Prepare and verify the closure through the existing backend image machinery.
  Online mode pulls each exact reference and verifies its local immutable
  reference and platform on the bound daemon. Offline-staged mode performs
  local daemon inspection only and keeps Compose `--pull never`; it must not
  call pull, manifest/registry inspection, build, tag, or any registry-facing
  fallback.
- Availability proof requires the exact local repo digest and a daemon-target
  compatible OS/architecture/variant. A tag, cache alias, config image ID,
  SBOM row, asset-lock row, or successful inspection of a differently named
  image is not proof of the requested manifest identity. Do not conflate an
  index digest, child manifest digest, and image config digest.
- Apply explicit finite deadlines to endpoint connection, image acquisition,
  Compose startup, spawned-child startup, and workflow execution/reconciliation.
  Lower the authored `RuntimeOrchestrationLifecyclePolicy` through the Docker
  authority adapter or reject the authority if its required policy cannot be
  enforced. Timeout must end accepted work in a terminal failed/timed-out
  state; merely stopping a poll while Shuffle remains `EXECUTING` is not a
  bounded outcome. A correlated child that is still running at observation is
  supervised until it becomes terminal or its authored deadline expires; the
  verifier never reports success while that child is still running.
- Keep the alert-to-case assertion in the existing scenario-verification
  answer-key seam. Its deadline, polling, evidence, and report lifecycle remain
  core-owned; Shuffle/TheHive-specific triggering and readback remain
  plugin-owned. Retry uses one stable correlation/idempotency identity and must
  not resubmit an uncorrelated webhook or create a second case.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Portable authority schema | RAES `RuntimeConfiguration`, `RuntimeControlInterface`, `RuntimeOrchestrationAuthority`, `RuntimeOrchestrationSpawnTemplate`, and `RuntimeOrchestrationLifecyclePolicy`, including RAES same-node semantic validation. Do not add APTL equivalents. |
| Plan interpretation | `interpret_provisioning_plan()`, `NodeRealization`, `AptlRealization`, `DeploymentNodeRealization`, and `DeploymentRealizationSpec`. Preserve runtime values rather than reconstructing them from Compose or seeds. |
| Trusted pre-plan facts | `raes_artifact_availability.py` and address-partitioned `ArtifactAvailabilityContext`. Extend exact-image demand collection without treating cache state as planning authority or fabricating node artifact satisfactions for spawned children. |
| Image realization | `raes_image_realization.py`, `_prepare_realization_images()`, `artifact_available()`, `_verify_staged_image()`, existing digest parsing, and the backend runner. Share exact acquisition/verification primitives, but keep node Compose overrides and child closure semantics separate. |
| Compose lowering | `_compose_node_generation.py`, generated realization files, `_validate_realization_compose_model()`, `docker compose config --format json`, project-directory/env-file scoping, and Compose `--pull never`. Validate the merged effective model, not only a renderer fragment. |
| Backend and daemon binding | `DeploymentBackend`, `DockerComposeBackend`, its typed `_run()` boundary, and existing appliance daemon-ID binding/inventory. No raw Docker subprocess belongs in the RAES adapter, verifier plugin, or seed scripts. |
| Runtime observation | `raes_runtime_observation.py`, `_runtime_mount_observation.py`, `_runtime_concern_excess.py`, and host-side `docker inspect`. The admitted control-interface mount is a separate allowed footprint, not an ordinary `runtime.mounts` declaration. All other excess mounts still fail closed. |
| Appliance boundary | ADR-049 and `appliance_boundary_inventory.py`: one guest daemon, exact authority-holder allow-list, no participant Docker access, and no host/remote daemon. The boundary helper and participant surfaces remain socket-free. |
| Config and secrets | Strict `AptlConfig`, existing `.env`/`EnvVars` hydration and placeholder checks, project containment, and Compose env-file scoping. The socket path, authority, child list, and image identity are typed plan/backend policy, not operator env overrides. |
| Lifecycles and waits | RAES lifecycle policy, `BackendTimeoutError`, typed backend timeouts, `wait_for_service()`, and scenario-verification monotonic deadlines. Do not create an independent Shuffle timeout loop in lab startup. |
| Errors and diagnostics | RAES `Diagnostic`/`render_raes_diagnostics()`, `ApplyResult`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, and existing CLI/API envelopes. Use stable bounded codes for invalid interface, endpoint change, child-image identity/absence/platform, and timeout; do not add an exception hierarchy. |
| Logging and persistence | `get_logger()`, `redact()`, `LocalRunStore`, range snapshots, and existing verification evidence/report storage. Persist safe identities, provenance, counts, daemon ID, timing, and verdicts; never persist raw inspect payloads, Docker stderr, environment values, or credentials. |
| Scenario proof | `scenario_verification.py`, the TechVault live-gate/plugin family, and service helpers. Core owns orchestration and evidence shape; the answer key owns the exact successful action-result and single-TheHive-case assertions. |

## Security And Validation Passage

The intended design must pass every layer below. Success at a later layer does
not compensate for omission at an earlier one.

| Layer | Required passage |
| --- | --- |
| RAES schema and semantics | Strict parsing and semantic validation preserve the interface, authority, reference, templates, privilege, and lifecycle fields. The join remains same-node and the portable pack remains the sole desired-state authority. |
| APTL provider admission | The interpreter rejects unsupported or ambiguous mappings before mutation, computes one management-only decision from the complete deployment graph, and carries it separately from the node-authored authority. It retains compiled resource addresses for bounded diagnostics and does not silently discard a recognized runtime field merely because RAES has no realization-concern key for it yet. |
| Backend security validator | A closed, engine-neutral dispatch selects the Docker/Unix adapter by typed enum values. That adapter accepts only the exact supported tuple and path. Adding a future endpoint is an explicit capability/allow-list change, not acceptance of arbitrary `bind_source`. |
| First-party config and secrets | Strict config and existing secret hydration remain unchanged. No credential, socket policy, product image list, or unvalidated host path is introduced through `aptl.json`, `.env`, seed content, or CLI passthrough. |
| OS-level exposure | The endpoint is a real accessible Unix socket with stable identity; every Docker call is pinned to it. The effective Orborus process targets the mounted endpoint. No TCP exposure, permission weakening, privileged mode, helper mount, participant route, or worker/app socket bind is admitted. |
| Exact image and platform gate | All node and child requirements are validated on the same daemon. Offline verification is local-only and proves the exact digest plus compatible platform. The complete closure passes before Compose startup. |
| Effective Compose gate | The generated and merged model contains one authorized read-write bind on exactly one service, with no duplicate/generalized mount and no endpoint-selecting environment conflict. Compose syntax success alone is insufficient. |
| Runtime excess and authority observation | Host-side inspect corroborates the authority holder, exact mount, access, endpoint and daemon identity. The mount-excess detector recognizes only an explicitly carried admission, never the node's raw RAES authority; unrelated, duplicate, ancestor, and resolved-alias mounts remain fatal. Spawned children are narrowed by authored image plus unique label, counted exactly, inspected for exact immutable image ID and no socket propagation, and supervised to a terminal state. |
| Appliance boundary | Authority remains inside one sealed guest and on its guest daemon. The participant/API, boundary helper, host, remote backend, and other scenario services do not gain Docker authority. Unsupported delivery modes fail closed. |
| Process, error, and logging boundary | Commands use argv lists and finite timeouts. Raw subprocess/registry/inspect data is reduced inside the backend to stable, bounded, redacted diagnostics. Existing CLI/API envelopes remain the only external error shapes. |
| Workflow and persistence boundary | One correlated execution reaches terminal success or terminal bounded failure. Evidence records non-empty successful action results, exactly one correlated TheHive case, retry outcome, and timings without persisting secrets or broad product payloads. |

Diagnostics should retain the existing `aptl.provisioner.*` namespace and
distinguish invalid/changed control interface, invalid/missing/mismatched or
platform-incompatible child image, and operation timeout. User-visible text is
bounded and names only safe compiled addresses/template identifiers and exact
image references; raw Docker output belongs only in redacted debug logging.

## Extensibility Seam

The seam is a pure closure/admission operation parameterized by:

`(compiled node address, RuntimeConfiguration, backend authority capabilities,
bound endpoint identity, offline policy)`

It yields the supported control-authority binding and a deduplicated set of
exact child-image requirements with origin provenance. The local Docker adapter
then lowers and verifies those values through existing backend operations. A
future engine, socket location, remote endpoint, or image-store implementation
must add a distinct capability implementation with equivalent identity,
platform, offline, observation, and timeout guarantees. It must not widen the
Docker adapter's path acceptance or introduce a TechVault/Shuffle branch.

## Gotchas And Forbidden Shortcuts

- Inherited `DOCKER_HOST`/Docker context can make availability and preparation
  target a different daemon from `/var/run/docker.sock`; binding only Compose
  is insufficient.
- `runtime.mounts` and `local_control_interfaces` are different concepts. Do
  not copy the socket into both to placate the excess-mount observer, and do not
  allow all control interfaces as ordinary binds.
- `DeploymentImageRealization` is service-image/Compose-override state. Do not
  create fake worker services or node artifact satisfactions to reuse it.
- `docker image inspect <tag>`, a matching image config ID, a lock/SBOM row, or
  a cache alias does not satisfy a digest-qualified child requirement.
- `docker manifest inspect`, pull-on-miss, tag repair, and registry fallback are
  network access and are forbidden in offline-staged mode.
- Static `docker-compose.yml` and `scripts/envpack-soar-fixups.sh` are not
  desired-state authorities. Do not extend their raw socket or mutable-image
  workarounds.
- Do not authorize by scenario name, node name, service name, known Shuffle
  image list, downstream seed, or currently running child containers.
- Do not use privileged mode, Docker-over-TCP, a generic proxy, chmod/chown, or
  socket propagation as substitutes for exact authority lowering.
- A preflight path check alone is vulnerable to replacement. Recheck identity
  at the mutation/start boundaries and corroborate post-start state. This
  bounds ordinary replacement races; it is not a claim to resist a hostile
  guest root that already owns the daemon.
- Container-running, port-open, or a terminal Shuffle status with empty action
  results is not end-to-end success. Polling must not retrigger case creation.
- Do not confuse Shuffle's external execution lifecycle with APTL's RAES
  `WorkflowEngine`; they share words such as execution/status but have
  different ownership and persistence contracts.

## Non-Goals And Boundaries

- No LilRAE change, env-pack authoring, Shuffle-specific image catalog, or
  replacement for the RAES portable schema.
- No general host-path mount feature, general container-orchestrator framework,
  Docker TCP support, remote/SSH Compose support for this authority, or relaxed
  appliance participant boundary.
- No redesign of ordinary node artifact satisfaction, SBOM generation, asset
  locks, or Compose service-image selection. If appliance archive production
  later carries spawned children, it must not represent them as fake Compose
  services; runtime daemon verification remains mandatory after import.
- No new public API, secret source, persistence store, exception hierarchy, or
  workflow engine.
- No production startup dependency on the TechVault seed or answer key. The
  seeded alert-to-case flow is end-to-end proof of the portable contract and
  retry safety, not an authority source or generic startup phase.
