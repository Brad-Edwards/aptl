# Issue #974 Shuffle Worker Authority And Offline Images Preflight

This note corrects the issue #949 design where the selected Shuffle runtime
requires a worker to use the same Docker daemon as Orborus and launches an app
by a product-native tag. It is architecture guidance, not an implementation
plan. The issue contract, the portable RAES model, and
[ADR-055](../adrs/adr-055-local-runtime-authority-and-ownership.md) are the
authorities.

The reusable machinery delivered for issue #949 remains the starting point,
but issue #974 supersedes its requirements for a pack-authored host
`bind_source`, `realized_children`, child counts, `docker-label:` evidence, no
worker socket, and no local tag operation in offline-staged mode.

## Architecture Decisions

- Preserve three independent inputs to effective realization: portable pack
  intent, evidenced backend capability and endpoint selection, and an explicit
  operator grant. A pack can request a Docker orchestration authority and name
  its in-world endpoint, environment, lifecycle, and spawn templates. It cannot
  select a host path, authorize a daemon mount, or grant delegation to a child.
  The `soc` interaction group is serving metadata under ADR-053, not a security
  grant.
- Reuse the RAES `RuntimeConfiguration` types without an APTL copy. Resolve the
  authority's control-interface reference on the same compiled node and admit
  the portable target endpoint. An empty `bind_source` is valid input. The
  backend selects a supported concrete source only after capability and
  operator-policy admission and carries that effective decision in
  `DeploymentDockerAuthorityAdmission`; it never writes the selection back into
  the portable runtime.
- Treat `spawn_templates` as desired workload/image inventory and
  `realized_children` as observations. Every authored template must name a
  digest-qualified reference. Neither admission nor image preparation may
  require authored child rows, expected counts, evidence strings, or APTL label
  syntax. Actual children are correlated and recorded after execution.
- Make delegated authority an explicit part of the effective operator grant.
  For this topology, Orborus is the authority holder and only the exact admitted
  worker template is eligible to receive the same endpoint. Application/action
  templates and unrelated services remain ineligible. Do not infer the worker
  from a product name, image repository, template `purpose`, network, service
  name, or interaction group. Use the ADR-055 local operator-policy contract,
  keyed to the immutable pack identity, compiled component address, authority
  ID, and template ID. Issue #956 extends this same policy model for container
  privilege fields; it must not create a parallel policy surface.
- Generate the authority correlation in the backend from the existing
  workspace/project and run/attempt identity. Shuffle 1.4.0 does not propagate
  arbitrary APTL metadata, so the trusted caller must bind the exact product
  execution ID returned by the accepted trigger to that admission. Shuffle then
  carries its supported `EXECUTIONID` unchanged on both the worker and app. A
  child belongs to the run only when that bound product ID, APTL run scope,
  template provenance, selected daemon, parent chain, and immutable image ID all
  agree. Timestamps, container names, `ancestor=` results, or image identity
  alone are not ownership evidence. A foreign or ambiguous child is never
  stopped, killed, reused, or counted as the run's child.
- Resolve the execution scope before authority admission. Reuse `AcesRunTarget`
  and the domain-separated `derive_identity()` machinery rather than inventing
  a pack label or conflating a Shuffle execution ID with an APTL run/attempt.
  The product ID is downstream evidence joined to the APTL-owned admission, not
  a substitute for it. An unbound or duplicate ID is foreign or ambiguous; it
  cannot authorize observation or lifecycle mutation.
- Derive both immutable and runtime image forms structurally from an authored
  `repository:tag@sha256:...` spawn reference. The full reference is identity;
  the `repository:tag` portion is a mutable execution alias. Do not maintain a
  Shuffle image catalog or synthesize a tag from template prose. If the
  product-native reference cannot be derived from the authored exact reference,
  the contract is incomplete and admission fails.
- Prepare every unique exact template image on the selected daemon and verify
  its repo digest, daemon-local image ID, and compatible platform through the
  existing exact-image machinery. For a required alias, accept an existing
  alias only when it resolves to that same image ID. Create an absent alias only
  from an already verified exact local image, then inspect it again. An alias
  that points elsewhere is stale or foreign: fail without overwriting it.
  Never use the mutable alias as artifact, provenance, SBOM, or satisfaction
  identity.
- Offline-staged preparation is a closed local operation: exact-reference
  inspect, optional local tag creation for an absent required alias, and alias
  inspect. It performs no pull, manifest lookup, build, registry fallback, or
  other network-capable image operation. The entire exact-image and alias
  closure must pass before workflow acceptance. Missing or mismatched exact
  images, failed local alias creation, and stale aliases are fatal.
- Keep Orborus socket lowering in the generated/effective Compose gate. The
  worker is created later by the product and therefore belongs to scoped child
  admission and observation, not a fake Compose service. Post-start observation
  must prove that Orborus and the admitted worker use the selected daemon and
  that app/action children and all unrelated services have no socket route,
  unadmitted Docker endpoint override, privileged substitute, or broader host
  bind. An authored `DOCKER_HOST` is acceptable only when it resolves to the
  exact admitted in-world endpoint; Docker contexts and remote endpoints remain
  unsupported.
- Record normalized actual-child observations after execution. A point-in-time
  empty `docker ps -a` result is not proof when the product can auto-remove a
  child; observation must occur while the child is inspectable or use bounded
  lifecycle evidence that retains its immutable ID, correlation, authority
  footprint, and terminal outcome. Lifecycle enforcement may act only on
  positively owned children.
- Keep workflow correctness in the existing scenario-verification seam. Core
  owns deadlines, polling, redaction, and report/evidence lifecycle; the
  TechVault answer key owns the Shuffle action-result and TheHive case
  semantics. Success requires one correlated execution to reach a terminal
  successful state with non-empty successful action results and exactly one
  correlated case. A terminal status alone is insufficient, and a retry must
  not submit a second uncorrelated workflow.

## Canonical Incumbents To Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| Portable schema and validation | RAES `RuntimeConfiguration`, `RuntimeControlInterface`, `RuntimeOrchestrationAuthority`, `RuntimeOrchestrationSpawnTemplate`, and lifecycle types; scenario-bundle/env-pack validation; RAES same-node semantic checks. Do not add APTL schema twins. |
| Plan and realization boundary | `interpret_provisioning_plan()`, `AptlRealization`, `DeploymentNodeRealization`, `DeploymentRealizationSpec`, and `runtime_authority.py`. Reshape the existing admission/image-demand DTOs; do not serialize a second plan or treat RAES observations as desired state. |
| Pack interaction | `pack_interaction.py` and the TechVault pack-interaction plugin. They may select serving groups only and must not authorize a mount or worker delegation. |
| Operator authority | The strict first-party policy/config seam from issue #956 and ADR-055. `ApplianceBoundaryPolicy` remains the signed appliance-specific policy; its holder-label allow-list is not a general local-start grant. |
| Config and secrets | `AptlConfig` models with `extra="forbid"`, existing `.env` hydration/placeholder checks, credential-file containment and permissions, and Compose env-file scoping. Authority grants and endpoint selection must not become ambient environment or CLI toggles. |
| Backend endpoint | `DeploymentBackend`, `DockerComposeBackend`, `_docker_endpoint_binding.py`, and the typed `_run()` boundary. Generalize backend-owned source selection there; no raw Docker subprocess belongs in a RAES adapter, verifier plugin, or seed script. |
| Image identity and preparation | `_docker_image_identity.py`, `_compose_spawn_image_realization.py`, existing platform normalization, endpoint revalidation, and backend timeouts. Add alias parsing/verification to this one identity boundary rather than creating another Docker-reference parser. Keep spawned images distinct from `DeploymentImageRealization`. |
| Effective lowering | `_compose_node_generation.py`, `_compose_model_realization.py`, generated realization files, `docker compose config --format json`, project/env-file scoping, and Compose `--pull never`. Static `docker-compose.yml` is not the env-pack contract. |
| Runtime containment | `_compose_runtime_observation.py`, `_compose_child_lifecycle.py`, `raes_runtime_observation.py`, `_runtime_mount_observation.py`, `_runtime_concern_excess.py`, and host-side inspect. Preserve the distinction between an admitted control endpoint and ordinary `runtime.mounts`. |
| Ownership and persistence | Existing Compose project/workspace identity, `AcesRunTarget`, `derive_identity()`, `LocalRunStore`, range snapshots, and existing no-follow/containment utilities. Persist only normalized observations and safe identities. |
| Workflow proof | `scenario_verification.py`, the TechVault verifier plugin, `collect_shuffle_executions()`, `collect_thehive_cases()`, and the existing live range-integration assertion. Do not put Shuffle/TheHive answer-key logic in deployment code. |
| Errors and observability | RAES `Diagnostic`/`render_raes_diagnostics()`, `ApplyResult`, `LabResult`, `StartupOutcome`, `StartupDiagnostic`, `BackendTimeoutError`, `get_logger()`, and `redact()`. Extend stable diagnostic conditions, not the exception or API hierarchy. |

## Security, Configuration, OS, And Error Passage

Passing a later layer never compensates for an omitted earlier layer.

| Layer | Required passage |
| --- | --- |
| Pack/schema | Strict pack and RAES validation preserves the target endpoint, environment, lifecycle, and all exact templates. `bind_source` and `realized_children` may be absent. Unknown or ambiguous authority/interface joins fail before mutation. |
| Capability | The selected backend truthfully declares support for the Docker/Unix/read-write/host-root-equivalent combination, local exact-image realization, alias handling, scoped child correlation, and observation. A partial implementation must not advertise the authority as supported. |
| Operator grant | A strict, independently supplied grant admits the authority holder, backend endpoint choice, daemon-image mutation, and the exact template eligible for delegation. Pack content, `soc`, ambient environment, and existing Docker state are not grants. |
| Backend selection | The backend maps the portable in-world target to one allowed source, records the decision separately, and rejects unsupported protocols, arbitrary sources, remote/TCP endpoints, duplicate targets, and cross-node references. |
| OS and process | `lstat`, socket type/access, device/inode, and daemon ID bind all Docker operations to one endpoint; identity is revalidated at mutation/start/observation boundaries. Commands use argv lists and finite timeouts, clear ambient Docker context, and never chmod/chown the socket or expose credentials in argv. |
| Exact images and aliases | Pull is allowed only online and only for authored exact references. Exact repo digest, local image ID, and platform pass before an alias is inspected or created. Alias absence permits local creation; an existing mismatch fails without overwrite. Offline command history contains no registry-capable operation. |
| Effective Compose | The merged model gives the exact endpoint only to the admitted Orborus service, permits only an endpoint environment value that resolves to that in-world target, contains no broader/duplicate mount, and keeps other declared services socket-free. Compose schema validity alone is not admission. |
| Spawned runtime | Exact run/attempt admission plus a caller-bound product `EXECUTIONID`, parent chain, and immutable image readback distinguish the delegated worker and app children. The worker has the one admitted route to the same daemon; app/action children and foreign children do not. Privileged mode, endpoint overrides, aliases to broader paths, and ancestor mounts remain fatal. |
| Lifecycle and ownership | Only positively owned children may be supervised or terminated. Foreign/uncertain state yields a diagnostic and zero destructive action. Actual observations survive product auto-removal sufficiently to prove outcome and authority footprint. |
| Errors, logs, and persistence | Docker/registry/inspect output is reduced inside the backend to bounded stable diagnostics. Existing CLI/API envelopes are retained. Logs and run evidence are redacted and never persist raw inspect payloads, full environment, Docker stderr, credentials, or control-plane secrets. |
| Workflow | The existing verification lifecycle proves terminal success, non-empty action results, and one correlated case within a bounded deadline. Failure, cancellation, or timeout becomes an explicit terminal failure and does not authorize an uncorrelated retry. |

Stable diagnostics should distinguish unsupported authority, missing operator
grant, endpoint selection/change, exact image missing/mismatch/platform,
required alias missing/stale, child ownership/correlation, unauthorized
authority propagation, and bounded timeout. Safe messages may identify compiled
addresses, authority/template IDs, and exact image references; raw subprocess
payloads stay out of user-facing results.

## Extensibility Seam

The seam remains the existing typed authority-admission boundary, evaluated
from:

`(pack identity, compiled node/runtime, backend capability and endpoint choices,
operator grant, workspace/run scope, offline policy)`

It yields a backend-selected endpoint, exact template image demands with
derived optional runtime aliases, explicit template-scoped delegation, and the
correlation scope needed for observation. Docker-specific lowering and readback
remain behind the deployment backend. A future engine or endpoint source adds
another capability implementation with equivalent identity, offline,
ownership, containment, and observation guarantees. It must not widen path
acceptance or add a TechVault/Shuffle conditional to shared core code.

## Gotchas And Forbidden Shortcuts

- Current normal local-start code has no independent operator grant for this
  authority. Do not interpret the appliance holder allow-list, a pack-interaction
  group, or `profiles <= {"soc"}` as the missing grant.
- A raw Docker socket gives daemon-wide authority. Template inventory and
  correlation labels improve admission and observation; they do not sandbox a
  compromised holder or worker. Preserve the selected backend/isolation
  disclosure from ADR-055.
- Do not copy `bind_source` back into the pack, require it in RAES, or accept an
  arbitrary pack-supplied host path for compatibility.
- Do not put generated child rows into `realized_children`, and do not retain
  the old one-to-one count or `docker-label:` parser under a different name.
- Do not authorize delegation by image/name/purpose heuristics. Only the
  independent exact operator grant can distinguish the worker template from the
  app template.
- A `repository:tag@digest` reference carries two roles. Parsing must preserve
  registry ports and nested repositories; naive colon splitting is incorrect.
  Repo digest, manifest-list digest, child-manifest digest, and config image ID
  remain distinct identity domains.
- Docker's `ancestor=` filter is broader than exact identity. Inspect every
  correlated child and compare its immutable local image ID.
- Never overwrite or delete a stale tag to “repair” a shared daemon. Absence is
  safely creatable after exact-image proof; disagreement is foreign/uncertain
  state and fails closed.
- A local `docker tag` does not contact a registry, but only the exact
  source-to-derived-alias form is allowed offline. Pull, manifest inspect,
  search, build, and fallback resolution are forbidden.
- Point-in-time post-run enumeration can miss auto-removed workers/apps. Empty
  observation must not become vacuous success, and lifecycle code must never
  kill a merely image-matching foreign container.
- Do not invent an APTL environment variable or label that Shuffle 1.4.0 cannot
  propagate. Bind only the product-supported `EXECUTIONID` returned by the
  trusted trigger, and keep the APTL run/attempt correlation in the effective
  admission and normalized observation.
- Do not add the socket to the app image, Shuffle backend, all spawned
  containers, static Compose, a seed script, or a product-wide default. Do not
  substitute privileged mode, Docker-over-TCP, a proxy, or an ancestor bind.
- Resolve run/workspace scope before generating labels. A Shuffle workflow
  execution ID is downstream evidence, not APTL resource ownership.
- Do not represent worker/app images as fake nodes, Compose services, ordinary
  artifact satisfactions, or `DeploymentImageRealization` entries merely to
  reuse another pipeline.
- Existing unit tests encode the superseded #949 contract. Replace the
  contradictory bind-source/child-count/blanket-socket assertions rather than
  layering #974 cases beside them. Negative coverage must include missing grant,
  missing/mismatched exact image, stale alias, foreign correlation, and
  unauthorized propagation; offline tests must assert absence of every
  registry-capable command.
- Container-running, port-open, or terminal Shuffle status with empty results
  is not success. The end-to-end proof must retain the existing one-case retry
  and idempotency guard.

## Non-Goals And Boundaries

- No env-pack authoring, RAES schema fork, APTL-specific portable label syntax,
  product image catalog, or fabricated runtime observation.
- No second operator-policy schema. Issue #974 establishes the bounded ADR-055
  local policy seam for daemon and template delegation; issue #956 must extend
  that same versioned model for its container privilege grants.
- No general host-path mount feature, remote Docker/TCP support, generic
  orchestrator framework, rootless-Docker claim, or claim that labels constrain
  a raw-socket holder.
- No relaxation of unrelated service/app isolation, runtime mount/environment
  closure, appliance participant boundaries, exact-image integrity, or
  offline-network policy.
- No redesign of node image satisfaction, SBOM/asset-lock identity, run-store
  format, exception hierarchy, public API, workflow engine, or seed lifecycle.
- No production startup dependency on TechVault answer-key behavior. The
  alert-to-case path is acceptance evidence for this contract, not an authority
  source or generic deployment phase.
