# Issue #974 Shuffle Worker Docker And Image Realization Preflight

This note fixes the repository-wide boundaries for issue #974. It is
architecture guidance, not an implementation plan. It supersedes the issue
#949 preflight only where that note requires a host `bind_source`, authored
`realized_children`, authored child labels/counts, one template per image,
digest-only templates, blanket rejection of a Docker socket on every spawned
  child, or prohibition of verified local alias creation while offline.
  ADR-055's three-party
authority rule, ADR-049's participant boundary, and issue #964's
native-resource ownership rules remain authoritative.

The motivating TechVault pack describes portable in-world intent: Orborus's
endpoint, environment, lifecycle, and authored spawn templates. It
does not select a host path, grant daemon authority, predict runtime children,
or define APTL correlation metadata.

## Keep The Contracts Separate

| Concept | Owner and meaning |
| --- | --- |
| Portable orchestration demand | RAES `RuntimeConfiguration`, `RuntimeControlInterface`, `RuntimeOrchestrationAuthority`, lifecycle policy, environment, and `spawn_templates`. These values describe the in-world endpoint and authored workload references; they are neither host authority nor an authorization inventory. |
| Backend capability | `DeploymentBackend` and the local Compose backend decide whether one selected daemon, endpoint lowering, image preparation, and runtime aliasing can be supported. Capability is not permission. |
| Operator grant | The bounded local policy proposed by ADR-055 is owned by #1129 and is not available in `dev`. Neither the pack nor this issue creates, narrows, or satisfies an operator grant. |
| Image identity | A digest-qualified reference is immutable identity. A tag in a tag-and-digest reference is an authored local runtime alias which must be made to resolve to that digest. A tag-only or digest-only reference is used as authored; a matching name string is never proof of local identity. |
| Runtime observation | Actual worker/app containers, counts, native IDs, status, image IDs, mounts, and correlations are backend observations made after execution. `realized_children` is not desired state, an image-preparation input, or an admission prerequisite. Runtime enumeration and ownership on a shared daemon remain #1128's boundary. |
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
  through effective Compose plus runtime inspect that APTL's lowered service
  reaches the bound daemon. A spawned worker is not a separately admitted
  service, a pack-authorized child, or an APTL-owned resource in this issue.
  Do not synthesize a second pack authority or reinterpret a spawn template as
  a grant.
- A raw Docker socket is host-root-equivalent authority over the selected
  daemon. The worker is therefore trusted at that boundary; read-only mount
  syntax, labels, networks, or container profiles do not attenuate it. The
  product adapter must fail admission when it cannot propagate the selected
  endpoint source faithfully (including a non-default/rootless source) rather
  than silently fall back to `/var/run/docker.sock` on another daemon.
- Effective Compose validation and post-start inspection remain default-deny
  for every other APTL-lowered service's socket bind, socket-containing
  ancestor bind, privileged container, or `DOCKER_HOST`/`DOCKER_CONTEXT`
  override. Do not extend that APTL service-containment gate into an invented
  policy over daemon-created children.
- Do not implement the operator-grant policy model in this issue. In particular,
  do not add a pack field, environment flag, CLI shortcut, hard-coded TechVault
  exception, or permissive default as a substitute. #1129 owns any future
  signed strict `DockerAuthorityPolicy` extension and its appliance projection;
  it must consume this typed edge rather than cause a parallel appliance grant.

### Exact images and runtime aliases

- Derive preparation demand from every `spawn_template`, even when
  `realized_children` is empty. Accept every RAES-valid authored image form:
  tag-and-digest, tag-only, and digest-only. Retain node/authority/template
  provenance for diagnostics and deduplicate work by authored reference. Do
  not require one template per image: two semantic templates may legitimately
  share immutable bytes.
- Keep `_compose_spawn_image_realization.py` as the realization owner and
  `_docker_image_identity.py` as the sole Docker-inspect parser. Online mode may
  pull the authored reference. Offline-staged mode may use only local daemon
  operations: no pull, manifest inspect, registry resolution, build, or
  fallback client is permitted.
- On the already bound daemon, use the canonical Docker inspect parser and
  platform checks. For a digest-qualified reference, prove its `RepoDigests`,
  config image ID, and platform. Where that authored reference also contains a
  tag, tag the verified local image with that authored tag, inspect both names,
  and require the same image ID. For tag-only or digest-only input, inspect and
  use exactly that input; do not manufacture a different alias or silently
  strengthen the pack contract.
- A stale alias must never pass: replace it using a local daemon tag operation
  and reverify it, or fail before workflow acceptance. Never pull the tag,
  accept a matching tag string as proof, or rewrite the exact identity to the
  tag.
- Image and alias preparation completes before the external Shuffle workflow
  can be accepted. Failure leaves the run unaccepted and emits one bounded
  diagnostic. Preparation must be idempotent on retry and must revalidate the
  socket/daemon before mutation so an alias cannot be created on a different
  daemon.
- `appliance/input_images.py` closure alignment is explicitly out of scope.
  Do not hide a change to its seed-script inventory or appliance archive
  contract inside this issue. Offline realization may only use already-local
  daemon operations and must fail cleanly when the authored image cannot be
  realized.

### Correlation, observation, and lifecycle

- Do not require the pack to author APTL label syntax, a positive count, or a
  future `realized_children` entry. Delete the corresponding rejection paths;
  do not replace them with a different correlation convention.
- Remove the spawned-child socket rejection. A raw-daemon holder can create a
  socket-holding child regardless of APTL staging, so this is neither an
  enforceable authorization boundary nor an actionable ownership fact.
- Existing `WorkspaceOwnership` / `ResourceReceipt` and lifecycle machinery
  remain the only route to observation or cleanup once #1128 defines shared
  daemon child ownership. This issue neither enumerates, claims, correlates,
  supervises, nor cleans up spawned children.
- Keep scenario success semantics in the installed TechVault verifier. The
  core deployment layer realizes the authored image/alias and preserves
  containment for services it lowers; the plugin proves terminal workflow
  success, non-empty action results, and exactly one run-correlated TheHive
  case.

## Cross-Cutting Layers The Design Must Pass

| Layer | Canonical incumbent | Required result |
| --- | --- | --- |
| Portable shape and semantics | Public RAES runtime models and processor validation in `raes_runtime_orchestration.py` | Same-node endpoint references, all RAES-valid authored image-reference forms, lifecycle/environment semantics, and closed model validation pass without an authored host source or child observation. No APTL mirror schema. |
| Environment and secret binding | `_environment_names()` / `_environment_defaults()` in `raes_base_substrate.py`, the existing credential boundary, Docker credential storage, and shared redaction | Alias selection comes from the authored image reference, never a secret or mutable Shuffle setting. Operator secrets remain name-only until credential binding and never enter image requirements, argv, diagnostics, or inspect logs. Registry credentials use the existing Docker client boundary only in online mode. |
| Deferred local policy shape | Strict `AptlConfig` models and the signed `ApplianceBoundaryPolicy` / `DockerAuthorityPolicy` family | #974 must not add a policy shape or treat pack data as policy. #1129 will make holder, delegated role, daemon scope, and image/tag mutation independently grantable and fail closed when absent. |
| Control-plane authentication | `verify_token`, the single-origin BFF Host/CSRF/session gates, and the authenticated lab lifecycle routes | This issue adds no endpoint or client-supplied authority field. A web-triggered lifecycle operation retains existing authentication; #1129, rather than request or pack content, will supply any server-side operator authorization. |
| Backend capability and endpoint | `DeploymentBackend`, `DockerComposeBackend`, `DockerEndpointBindingMixin` | One supported local Unix endpoint is selected and pinned by socket plus daemon identity. Non-local schemes, symlinks, inaccessible sockets, swaps, and unsupported product propagation fail closed. |
| Effective configuration | `render_realization_compose()`, Compose-config validation, and `_compose_runtime_orchestration.py` | The backend-selected source is mounted only on the APTL-lowered holder; the in-world target remains authored. No static-Compose fallback or pack-controlled host path. |
| OS/process boundary | `DockerComposeBackend._run()` / `_subprocess_kwargs()` and bounded deployment timeouts | Docker calls use argv lists and the pinned `DOCKER_HOST`, clear conflicting context, and never place secrets or untrusted shell fragments in argv. Image refs/tags are validated data, not command text. |
| Image identity | `_compose_spawn_image_realization.py`, `_compose_image_realization.py`, `_docker_image_identity.py` | Extend the canonical local-inspect parser rather than adding tag-string checks. Verify digest identity when authored; create and re-inspect the authored tag alias only for tag-and-digest input. Offline mode has no registry-capable branch. |
| Runtime authority observation | `_compose_runtime_observation.py`, `runtime_authority.py`, and RAES runtime observation | APTL-lowered holders retain their existing containment checks. Spawned-child label/count/socket checks are removed, without treating children as observed or owned; #1128 owns any later child-runtime boundary. |
| Ownership and persistence | `_compose_resource_ownership.py`, `_compose_resource_resolution.py`, lifecycle storage, ACES run/attempt identity | Preserve these controls for APTL-owned resources. Do not use labels, tags, counts, or names to claim a spawned child in #974. |
| Appliance materialization | `appliance/input_images.py`, `appliance/inputs.py`, release manifest validation, and `aptl-appliance-first-boot` | Preserve the existing signed staged closure. Its alignment to spawn templates is expressly out of scope; #974's offline path still cannot contact a registry. |
| Errors and logs | `LabResult`, RAES `Diagnostic`, `BackendTimeoutError`, `get_logger()`, and redaction utilities | Expose stable stage/reason/provenance identifiers, not raw Docker stderr, inspect payloads, environment values, host paths, registry credentials, or secrets. Timeout and offline-unavailable are distinct fail-closed outcomes. |
| Workflow verification | `techvault_live_gate.py`, scenario verifier plugin seam, and existing bounded polling | Workflow acceptance happens only after preparation; semantic success remains plugin-owned and run-correlated rather than hard-coded in deployment core. |

## Canonical Reuse And Extensibility Seam

The generic image layer's durable seam is an immutable tuple of `(authored image
reference, selected daemon identity, offline mode, provenance)`, plus the
canonical locally inspected identity. The one derived alias is the tag already
present in a tag-and-digest authored reference; it is not a Shuffle default or
a new portable field. A future image-reference form extends the one canonical
Docker reference/inspect path, not a product-specific tag parser.

The authority seam for this issue remains portable demand plus backend
capability for services APTL actually lowers. #1129 may add its independent
operator-grant intersection there. Do not add child roles, delegation edges,
or child-image authorization to this seam: raw daemon authority cannot be
bounded by them.

Reuse rather than duplicate:

- RAES runtime models and reference validation, not local portable DTO copies;
- `DockerEndpointBindingMixin`, not another socket/daemon resolver;
- Docker image identity/parsing and platform checks, extended once for the
  authored tag/digest distinction rather than reimplemented as tag-string logic;
- `WorkspaceOwnership` and `ResourceReceipt`, not labels as ownership or a new
  child registry;
- strict config/appliance boundary policy, not environment booleans;
- `LabResult`/RAES diagnostics, bounded timeouts, logging/redaction, and the
  existing live-gate plugin seam, not a parallel exception or workflow stack;
- existing offline staging guards, not seed-script inspection or shell repair.

## Required Verification Guardrails

Tests must cover both online and offline image paths, exact identity versus
alias state, and removal of the invalid SDL rejections. #1129 owns the
independent operator-grant decision and #1128 owns child ownership/observation.
At minimum, prove:

- tag-only, digest-only, and tag-and-digest template values all realize as
  authored; `realized_children` without templates does not create an image
  closure or fail admission;
- a missing exact image or stale tag alias fails, or the alias is replaced by
  a local tag operation and reinspection proves the expected image ID;
- offline staging invokes no registry-capable command or client and fails
  before workflow acceptance when local preparation cannot complete;
- `evidence_ref` and `count` are passed through RAES rather than parsed as
  APTL Docker-label/count policy, and a spawned child with a socket no longer
  triggers this issue's rejection;
- the clean TechVault live gate reaches terminal success with non-empty action
  results and exactly one case for the current run.

Prefer command-recording unit tests for the zero-registry invariant plus a real
isolated-daemon integration test for image IDs and local tags. A mocked
`docker inspect` transcript alone does not prove Docker's alias semantics.

## Gotchas And Anti-Patterns

- Do not use `realized_children` as desired state, preparation input, expected
  count, permission, or ownership evidence.
- Do not put host paths, operator grants, APTL labels, workspace IDs, or
  attempt IDs in the portable pack.
- Do not treat `DOCKER_HOST`, `soc`, a private network, a read-only mount, or a
  digest-qualified image as an authority grant.
- Do not model a worker or app as an APTL-admitted/authorized spawned child;
  the daemon holder can create either regardless of the staged image list.
- Do not accept a runtime tag's existence, name, or registry digest lookup as
  proof of its local target. Inspect the local image ID after aliasing.
- Do not let offline mode fall through to `docker pull`, `docker manifest
  inspect`, registry HTTP, a library resolver, or tag auto-download.
- Do not parse `seed-shuffle.sh`, duplicate the HTTP 1.4.0 fact in backend
  defaults, or edit static `docker-compose.yml` as a fallback fix.
- Do not correlate or clean up by image, label, count, name, or timestamp
  alone; #974 does not enumerate children at all.
- Do not expose Docker stderr, full inspect JSON, environment arrays, selected
  host paths, credentials, or raw workflow results in diagnostics/logs.
- Do not hard-code TechVault workflow/TheHive semantics in deployment core or
  turn the verifier into an image/authority controller.

## Non-Goals And Boundaries

- This issue does not make raw Docker authority safe, attenuated, or suitable
  for participant workloads; it records one trusted Shuffle management topology
  for later intersection with operator policy.
- It does not define the general local policy vocabulary owned by #1129, accept
  ADR-055, or authorize a permissive interim substitute.
- It does not implement shared-daemon child enumeration, ownership,
  correlation, observation, or cleanup (#1128).
- It does not redesign RAES runtime schemas, require packs to author backend
  observations, or add APTL-specific portable fields.
- It does not generalize arbitrary remote/TCP Docker endpoints, Docker contexts,
  Kubernetes, Podman, registries, or cross-daemon image transfer.
- It does not align `appliance/input_images.py` with spawn templates.
- It does not change Shuffle workflows, seed application content, TheHive
  semantics, or scenario success criteria beyond making their selected runtime
  executable and verifiable.
- It does not replace backend ownership/cleanup, appliance signing, lifecycle,
  live-gate, logging, redaction, or error-envelope conventions.
