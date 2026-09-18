# Issue #974 Shuffle Worker Docker And Image Realization Preflight

This note fixes the repository-wide boundaries for issue #974. It is
architecture guidance, not an implementation plan. It supersedes the issue
#949 preflight only where that note requires a host `bind_source`, authored
`realized_children`, authored child labels/counts, one template per image,
blanket rejection of a Docker socket on every spawned child, or prohibition
of verified local alias creation while offline. ADR-055's three-party
authority rule, ADR-049's participant boundary, and issue #964's
native-resource ownership rules remain authoritative.

The motivating TechVault pack describes portable in-world intent: Orborus's
endpoint, environment, lifecycle, and digest-qualified spawn templates. It
does not select a host path, grant daemon authority, predict runtime children,
or define APTL correlation metadata.

## Keep The Contracts Separate

| Concept | Owner and meaning |
| --- | --- |
| Portable orchestration demand | RAES `RuntimeConfiguration`, `RuntimeControlInterface`, `RuntimeOrchestrationAuthority`, lifecycle policy, environment, and `spawn_templates`. These values describe the in-world endpoint and exact workload inventory. |
| Backend capability | `DeploymentBackend` and the local Compose backend decide whether one selected daemon, endpoint lowering, image preparation, runtime aliasing, and product-required delegation can be supported. Capability is not permission. |
| Operator grant | The bounded local policy from issue #956 / ADR-055 independently permits the admitted holder and the narrowly identified Shuffle worker delegation. The pack cannot create, narrow, or satisfy this grant. |
| Image identity | A digest-qualified reference is immutable identity. A product-native tag is a mutable local runtime alias that must resolve to the same inspected image ID; it is never identity or admission evidence. |
| Runtime observation | Actual worker/app containers, counts, native IDs, status, image IDs, mounts, and correlations are backend observations made after execution. RAES `realized_children` may report observations; it is not desired state or an admission prerequisite. |
| Resource ownership | Existing workspace/project/attempt identity and durable native-ID receipts establish which resources APTL may observe or clean up. A pack label, tag, name, timestamp, or count does not. |

Do not collapse these concepts into one enlarged authority DTO. In particular,
image preparation requirements must not carry future child counts or authored
APTL labels, and observed child records must not become the source of image
demand.

## Architecture Decisions And Guardrails

### Authority and endpoint selection

- Preserve the existing RAES parse/semantic-validation boundary. Resolve an
  authority's endpoint reference on the same node and validate the portable
  endpoint target, access, engine, privilege class, lifecycle, environment,
  and exact templates without copying the RAES models into APTL.
- Treat `local_control_interfaces.bind_source` as optional portable input, not
  host policy. The effective source comes only from the backend's selected
  local endpoint. A pack-supplied source must never redirect Docker commands,
  grant a mount, or constrain operator policy. Compatibility parsing of a
  legacy value does not make it authoritative.
- Reuse `DockerEndpointBindingMixin` for explicit `docker_socket_path` /
  supported local `DOCKER_HOST` selection, `lstat` no-symlink socket checks,
  read/write accessibility, device/inode pinning, daemon-ID attestation, and
  revalidation. Endpoint selection and operator authorization are separate:
  an ambient `DOCKER_HOST` can select a candidate but cannot grant it.
- Realize the selected source at Orborus's authored in-world target and prove
  through effective Compose plus runtime inspect that Orborus reaches the
  bound daemon. The selected Shuffle topology also requires its worker to
  reach that same daemon. Admit this as one explicit, product-required
  delegation edge under the independent operator grant; do not synthesize a
  second pack authority or reinterpret a spawn template as a grant.
- A raw Docker socket is host-root-equivalent authority over the selected
  daemon. The worker is therefore trusted at that boundary; read-only mount
  syntax, labels, networks, or container profiles do not attenuate it. The
  product adapter must fail admission when it cannot propagate the selected
  endpoint source faithfully (including a non-default/rootless source) rather
  than silently fall back to `/var/run/docker.sock` on another daemon.
- The delegation allow-set is closed: Orborus and the correlated Shuffle
  worker are admitted; Shuffle app/action containers, unrelated scenario
  services, backend apparatus, and participant workloads are not. Effective
  Compose validation and post-start inspection remain default-deny for every
  other socket bind, socket-containing ancestor bind, privileged container,
  or `DOCKER_HOST`/`DOCKER_CONTEXT` override.
- Consume the canonical operator grant introduced by issue #956. Do not add a
  second pack field, environment flag, CLI shortcut, hard-coded TechVault
  exception, or permissive default. Appliance mode must extend/reuse the
  signed strict `DockerAuthorityPolicy` family rather than inventing a parallel
  appliance grant. Until the relevant grant is present, admission fails before
  deployment mutation.

### Exact images and runtime aliases

- Derive preparation demand from every admitted `spawn_template`, even when
  `realized_children` is empty. Require canonical digest-qualified references,
  retain node/authority/template provenance for diagnostics, and deduplicate
  acquisition work by exact reference. Do not require one template per image:
  two semantic templates may legitimately share immutable bytes.
- Keep `_compose_spawn_image_realization.py` as the realization owner and
  `_docker_image_identity.py` as the sole Docker-inspect parser. Online mode may
  pull the exact reference. Offline-staged mode may use only local daemon
  operations: no pull, manifest inspect, registry resolution, build, or
  fallback client is permitted.
- On the already bound daemon, verify the exact reference's `RepoDigests`,
  config image ID, and platform before creating or accepting any runtime alias.
  A required product-native tag is a backend-derived binding from the admitted
  Shuffle environment/template metadata to that exact reference. Never infer
  it from `scripts/seed-shuffle.sh`, a live cache, a container name, or a
  mutable backend default.
- Establish an alias locally from the verified exact image, then inspect both
  names and require the same image ID. A stale alias must never pass: either
  replace it under the admitted image-mutation capability and reverify it, or
  fail before workflow acceptance. Never pull the tag, accept a matching tag
  string as proof, or rewrite the exact identity to the tag.
- Image and alias preparation completes before the external Shuffle workflow
  can be accepted. Failure leaves the run unaccepted and emits one bounded
  diagnostic. Preparation must be idempotent on retry and must revalidate the
  socket/daemon before mutation so an alias cannot be created on a different
  daemon.
- The appliance OCI input closure must consume the same exact spawn-template
  inventory. `appliance/input_images.py` must not parse the seed script or
  reconstruct child images from `SHUFFLE_BASE_IMAGE_NAME`. First boot may
  `docker load` the exact archive and establish local aliases through the same
  backend preparation path; it must not add an appliance-only image contract.

### Correlation, observation, and lifecycle

- Generate correlation from the existing workspace, Compose project, attempt,
  and ACES run identities. Carry a fresh execution correlation through the
  product-native workflow boundary and observe the native worker/action
  relationship after execution. Do not require the pack to author APTL label
  syntax, a positive count, or a future `realized_children` entry.
- Persist actual native container IDs and the bound daemon identity through the
  existing `WorkspaceOwnership` / `ResourceReceipt` lifecycle store before
  treating a child as owned. Observation may then record exact image ID,
  runtime role, mounts, state, and actual count. It must not create a second
  ownership database or keep the only correlation in a reusable backend
  instance.
- Product-native correlation and Docker events/metadata are discovery
  evidence, not a cryptographic security boundary: a raw-daemon authority can
  forge Docker labels. Resolve candidates inside the current daemon,
  workspace/attempt/run and accepted execution scope, pin native IDs, and
  revalidate before observation or cleanup. A foreign, stale, ambiguous, or
  unowned candidate is a bounded conflict and receives no mutation.
- Replace the blanket spawned-child socket rejection with role-aware
  observation against the closed delegation allow-set. The correlated worker
  must have exactly the selected endpoint route and no alternate daemon route;
  app/action children must have none. Unexpected socket propagation,
  privileged mode, ancestor binds, endpoint overrides, changed daemon identity,
  or a socket on an unrelated service fails the runtime gate.
- Reuse the existing lifecycle deadline and child-cleanup machinery, but drive
  it from durable owned native IDs and actual observations. Authored lifecycle
  policy still bounds execution; it does not predict child cardinality.
- Keep scenario success semantics in the installed TechVault verifier. The
  core deployment layer proves authority, ownership, image, alias, and runtime
  containment; the plugin proves terminal workflow success, non-empty action
  results, and exactly one run-correlated TheHive case.

## Cross-Cutting Layers The Design Must Pass

| Layer | Canonical incumbent | Required result |
| --- | --- | --- |
| Portable shape and semantics | Public RAES runtime models and processor validation in `raes_runtime_orchestration.py` | Same-node endpoint references, exact image references, lifecycle/environment semantics, and closed model validation pass without an authored host source or child observation. No APTL mirror schema. |
| Environment and secret binding | `_environment_names()` / `_environment_defaults()` in `raes_base_substrate.py`, the existing credential boundary, Docker credential storage, and shared redaction | Alias selection consumes only validated non-secret Shuffle configuration. Operator secrets remain name-only until credential binding and never enter image requirements, argv, diagnostics, inspect logs, or persisted correlation. Registry credentials use the existing Docker client boundary only in online mode. |
| Local policy shape | Strict `AptlConfig` models and issue #956's ADR-055 grant; signed `ApplianceBoundaryPolicy` / `DockerAuthorityPolicy` in appliance mode | Unknown keys fail; holder, delegated role, daemon scope, and image/tag mutation are independently granted. Missing grant fails before mutation. Pack data never populates policy. |
| Control-plane authentication | `verify_token`, the single-origin BFF Host/CSRF/session gates, and the authenticated lab lifecycle routes | This issue adds no endpoint or client-supplied authority field. A web-triggered lifecycle operation retains existing authentication, but authorization still comes from server-side operator policy rather than request or pack content. |
| Backend capability and endpoint | `DeploymentBackend`, `DockerComposeBackend`, `DockerEndpointBindingMixin` | One supported local Unix endpoint is selected and pinned by socket plus daemon identity. Non-local schemes, symlinks, inaccessible sockets, swaps, and unsupported product propagation fail closed. |
| Effective configuration | `render_realization_compose()`, Compose-config validation, and `_compose_runtime_orchestration.py` | The backend-selected source is mounted only where granted; the in-world target remains authored. No static-Compose fallback or pack-controlled host path. |
| OS/process boundary | `DockerComposeBackend._run()` / `_subprocess_kwargs()` and bounded deployment timeouts | Docker calls use argv lists and the pinned `DOCKER_HOST`, clear conflicting context, and never place secrets or untrusted shell fragments in argv. Image refs/tags are validated data, not command text. |
| Image identity | `_compose_spawn_image_realization.py`, `_compose_image_realization.py`, `_docker_image_identity.py` | Exact digest, image ID, and platform are verified on the selected daemon; aliases are local mutable bindings verified to that ID. Offline mode has no registry-capable branch. |
| Runtime authority observation | `_compose_runtime_observation.py`, `runtime_authority.py`, and RAES runtime observation | Orborus and the correlated worker reach the same admitted daemon. Every other service/action is proven free of ungranted socket/override/privileged access. Actual children are reported after execution. |
| Ownership and persistence | `_compose_resource_ownership.py`, `_compose_resource_resolution.py`, lifecycle storage, ACES run/attempt identity | Native IDs are durably bound to daemon/workspace/project/attempt/run before later observation or cleanup. Foreign correlation cannot authorize mutation. |
| Appliance materialization | `appliance/input_images.py`, `appliance/inputs.py`, release manifest validation, and `aptl-appliance-first-boot` | Exact template images are in the signed staged closure; first boot loads locally and reuses normal alias verification without a registry request. |
| Errors and logs | `LabResult`, RAES `Diagnostic`, `BackendTimeoutError`, `get_logger()`, and redaction utilities | Expose stable stage/reason/provenance identifiers, not raw Docker stderr, inspect payloads, environment values, host paths, registry credentials, or secrets. Timeout and offline-unavailable are distinct fail-closed outcomes. |
| Workflow verification | `techvault_live_gate.py`, scenario verifier plugin seam, and existing bounded polling | Workflow acceptance happens only after preparation; semantic success remains plugin-owned and run-correlated rather than hard-coded in deployment core. |

## Canonical Reuse And Extensibility Seam

The generic image layer's durable seam is an admitted immutable tuple of
`(exact image reference, zero or more required local runtime aliases, selected
daemon identity, offline mode, provenance)`. The Shuffle-facing adapter derives
aliases from validated admitted runtime environment/template data. A future
Shuffle app version or another product-native alias changes data or adds a
product adapter; it does not add tag parsing to the generic Docker identity
code or a special case to the appliance builder.

The authority seam is the effective intersection of portable demand, backend
capability, and typed operator grant, with a closed set of role/delegation edges
bound to one selected endpoint. A future product-required helper can add a
reviewed role edge through that seam. It must not broaden authority to every
spawned child or require editing the portable RAES schema to carry host policy.

Reuse rather than duplicate:

- RAES runtime models and reference validation, not local portable DTO copies;
- `DockerEndpointBindingMixin`, not another socket/daemon resolver;
- Docker image identity/parsing and platform checks, not tag-string logic;
- `WorkspaceOwnership` and `ResourceReceipt`, not labels as ownership or a new
  child registry;
- strict config/appliance boundary policy, not environment booleans;
- `LabResult`/RAES diagnostics, bounded timeouts, logging/redaction, and the
  existing live-gate plugin seam, not a parallel exception or workflow stack;
- the canonical appliance input closure and first-boot loader, not seed-script
  inspection or shell repair.

## Required Verification Guardrails

Tests must cover the two independent decisions (capability and operator grant),
both online and offline image paths, exact identity versus alias state, and
pre-/post-execution observation. At minimum, prove:

- omission of `bind_source` and `realized_children` does not remove the exact
  image closure or authority demand;
- missing operator grant prevents mutation, while an admitted Orborus/worker
  pair uses one pinned daemon and app/unrelated containers have no authority;
- missing or mismatched exact images fail, and a stale alias is never accepted
  without safe local replacement plus reinspection;
- offline staging invokes no registry-capable command or client and fails
  before workflow acceptance when local preparation cannot complete;
- foreign/stale execution correlation cannot become an ownership receipt or
  cleanup target;
- the clean TechVault live gate reaches terminal success with non-empty action
  results and exactly one case for the current run.

Prefer command-recording unit tests for the zero-registry invariant plus a real
isolated-daemon integration test for image IDs, tags, socket propagation, and
foreign resources. A mocked `docker inspect` transcript alone does not prove
the selected Shuffle topology.

## Gotchas And Anti-Patterns

- Do not use `realized_children` as desired state, preparation input, expected
  count, or permission.
- Do not put host paths, operator grants, APTL labels, workspace IDs, or
  attempt IDs in the portable pack.
- Do not treat `DOCKER_HOST`, `soc`, a private network, a read-only mount, or a
  digest-qualified image as an authority grant.
- Do not grant every spawned container because the selected worker needs the
  socket; worker and app roles are different security principals.
- Do not accept a runtime tag's existence, name, or registry digest lookup as
  proof of its local target. Inspect the local image ID after aliasing.
- Do not let offline mode fall through to `docker pull`, `docker manifest
  inspect`, registry HTTP, a library resolver, or tag auto-download.
- Do not parse `seed-shuffle.sh`, duplicate the HTTP 1.4.0 fact in backend
  defaults, or edit static `docker-compose.yml` as a fallback fix.
- Do not correlate or clean up by image, label, count, name, or timestamp alone;
  do not mutate a foreign candidate to make it fit.
- Do not expose Docker stderr, full inspect JSON, environment arrays, selected
  host paths, credentials, or raw workflow results in diagnostics/logs.
- Do not hard-code TechVault workflow/TheHive semantics in deployment core or
  turn the verifier into an image/authority controller.

## Non-Goals And Boundaries

- This issue does not make raw Docker authority safe, attenuated, or suitable
  for participant workloads; it deliberately admits one trusted Shuffle
  management topology under operator policy.
- It does not define the general local policy vocabulary owned by issue #956,
  accept ADR-055, or authorize a permissive interim substitute.
- It does not redesign RAES runtime schemas, require packs to author backend
  observations, or add APTL-specific portable fields.
- It does not generalize arbitrary remote/TCP Docker endpoints, Docker contexts,
  Kubernetes, Podman, registries, or cross-daemon image transfer.
- It does not change Shuffle workflows, seed application content, TheHive
  semantics, or scenario success criteria beyond making their selected runtime
  executable and verifiable.
- It does not replace backend ownership/cleanup, appliance signing, lifecycle,
  live-gate, logging, redaction, or error-envelope conventions.
