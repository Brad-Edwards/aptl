# Issue #964 Backend Resource Ownership Preflight

This note fixes the architecture boundary for backend resource ownership. It is
guidance, not an implementation plan. The issue contract is authoritative.
[ADR-055](../adrs/adr-055-local-runtime-authority-and-ownership.md) establishes
the general ownership rule; ADR-023 owns container interaction, ADR-046/048 own
scenario realization, issue #905 owns lifecycle serialization and recovery,
and issue #949 owns runtime-orchestration admission. This change must join
those contracts without changing SDL identity or creating a second scenario,
realization, lifecycle, or error model.

## Architecture Decisions And Boundaries

### Keep semantic identity, backend namespace, and native identity separate

Three identities currently collapse into `container_name`. They must remain
distinct:

| Identity | Owner and meaning |
| --- | --- |
| Scenario identity | RAES/SDL node address, authored node/host/service names, network aliases, relationships, and authored labels. These retain their portable meaning and are not collision tokens. |
| Backend ownership scope | APTL's stable workspace identity, validated logical deployment project, selected daemon identity, and current attempt/run identity. These authorize discovery and recovery; authors do not supply them. |
| Native resource identity | The daemon-issued immutable container ID (and the equivalent provider identity for another backend) captured after creation. All later interaction and destructive work targets this identity, never a re-resolved name. |

`DeploymentNodeRealization`, `BaseContainerSpec`, and the RAES runtime models
remain the semantic desired-state contracts. Do not add workspace or attempt
fields to RAES, reinterpret `aptl.node.address` as authority, or create a
second node DTO. The backend may keep a request-scoped binding from the
existing compiled node address to its external implementation name and native
ID. That binding is backend control state, not scenario evidence.

`DeploymentConfig.project_name` is currently both a user-facing logical name
and the Compose namespace. It is validated but defaults to `aptl`, so it does
not distinguish two workspaces. Treat it as the logical project component and
derive one bounded effective backend namespace from it plus an APTL-owned,
stable workspace identity. The workspace identity is minted and recovered
through contained, no-follow, owner-only `.aptl/lifecycle` state; invalid or
ambiguous existing state fails closed rather than silently generating new
cleanup authority. The effective namespace, not the authored node name, scopes
Compose project labels, generated container/network/volume names, and
backend-owned files. Preserve scenario-visible hostname and network aliases.
If a scenario requires an exact native name that the selected shared daemon
cannot provide without collision, require an isolated daemon/namespace or
return a materialization conflict before mutation.

Use the already resolved `AcesRunTarget.run_id` as the realization attempt
identity. Do not mint another backend "execution" ID or confuse it with the
workflow engine's internal run ID. The lab-start fallback run ID must be
collision-resistant rather than timestamp-only before it can authorize native
resources. Retry within the same admitted start retains the attempt identity;
a separately admitted start receives a new one. Stop and recovery may clean all
durably recorded resources owned by the workspace/project, while child
observation and deadline enforcement remain restricted to the exact attempt.

### Ownership is a checked chain, not a label predicate

Labels and scoped names narrow discovery, but neither proves ownership. An
owned object must be joined through this chain:

`bound daemon -> workspace -> effective project -> attempt when applicable ->
recorded native resource ID -> freshly inspected type/owner/semantic binding`

Creation is the authority-producing event. Capture the native ID from the
create/readback boundary and durably record it before proceeding to the next
side effect. Compose-created resources require a complete checked post-create
inventory bound to the unique effective project namespace; ambiguous,
uninspectable, or extra candidates fail realization. The ownership receipt is
a small versioned backend lifecycle record under `.aptl`, written atomically
through the existing path-containment conventions. It is not a run-evidence
schema and must not be placed in or mutate a sealed `LocalRunStore` archive.

On later lookup, query by scoped implementation name or APTL labels only to
find a candidate. Inspect the candidate, verify the bound daemon and complete
owner tuple, capture its native ID, and use that ID for reuse, attachment,
exec, copy, logs, restart, observation, stop, kill, or removal. Re-inspecting
by name after validation reopens the replacement race. An operation by the
recorded ID must fail if that object disappeared; it must never fall through to
a same-name replacement. Where Docker has no immutable per-object ID usable by
the operation, use a workspace-scoped external name plus an isolated
daemon/namespace when replacement could otherwise cross ownership; uncertainty
is a conflict, not cleanup permission.

`_base_container_already_realized()` may reuse only the exact recorded native
ID after owner, address, running state, and exact image identity all match.
Inspect failure, malformed labels, missing receipt, stopped state, wrong image,
or a different ID is not "absent." It yields a bounded conflict or stale-owned
state for explicit recovery. `start_base_container()` must not issue
`docker rm -f <authored-name>` to clear any of those states. Create must use
Docker's atomic name-conflict behavior; a collision fails without first
deleting the candidate. Failed-create rollback removes only IDs recorded as
created by that attempt.

The same rule applies to the generic container operations in
`ComposeQueryMixin`. `container_exists()` followed by `container_exec(name)` is
not one authorization decision. CLI logs/shell, provider exec, copy/file read,
network reconciliation, health/readiness, autoremove, snapshots, and restart
must resolve an owned native handle and retain it through the action. Public
container selection may continue to accept a scenario-facing name, but the
backend converts it once to an owned handle; a generic raw `container_inspect`
remains an internal provider primitive and must not be treated as an ownership
check.

### Runtime-spawned children require independent backend ownership

Issue #974 supersedes issue #949's authored `child_label` and count contract.
Exact authored spawn-template images remain preparation/conformance inputs;
actual children and counts are post-execution observations. Backend-generated
run/execution correlation must first restrict discovery to the current daemon,
workspace, attempt, run, and accepted product execution. Every selected child
is then recorded in the existing ownership receipt, pinned by native ID, and
revalidated before observation or termination.

An APTL-controlled opaque owner marker may be used only where the admitted
runtime contract permits that backend metadata and its observability does not
change closed/exact SDL semantics. It must be independent of the authored
content and impossible for a prior attempt's stale marker to satisfy the
current receipt. Do not rewrite, overload, or require authors to add the
marker. A runtime authority with the raw daemon socket can see and forge
ordinary Docker labels, so label secrecy is not an ownership boundary.

When the child producer cannot carry trustworthy attempt ownership without an
SDL-observable change, select a daemon/namespace dedicated to the admitted
workspace/attempt and bind that isolation into the ownership receipt. On the
ordinary shared host daemon, exact image plus product correlation metadata is
insufficient by itself: admission or post-start verification must report the
backend resource/materialization conflict before APTL observes, waits on,
stops, or kills a candidate. A timestamp window, child count, container name,
ancestor filter, or parent-holder identity does not repair this gap.

### Teardown and recovery use receipts, not broad cleanup authority

The lifecycle lock prevents overlapping mutation in one workspace but does
not establish daemon ownership and does not serialize two workspaces. Keep it,
and add no second lock namespace. Normal stop, failed-start rollback, clean
boot, emergency kill, autoremove, and delayed deadline enforcement all consume
the same backend ownership receipts. Label queries return candidates for
verification; bulk `docker rm` over query output and unqualified
`docker compose down -p <logical-name>` are not safe destructive primitives on
a shared namespace.

Cleanup attempts every recorded owned resource, records bounded residuals, and
proves absence by native ID. A missing owned ID is already absent; a same-name
or same-label replacement is foreign and remains untouched. An uninspectable
candidate, incomplete/corrupt receipt, changed daemon, or inventory error is
"cleanup authority unknown," never successful absence. Do not use a foreign
object to unblock network, volume, or name cleanup. A cleanup conflict may
leave owned residue and return an actionable failure; it may not broaden the
scope.

For provider-managed aggregate operations that cannot target the recorded
native set without rediscovery, use the effective workspace namespace only
inside a provider isolation boundary that makes the aggregate exclusive.
Otherwise replace the aggregate with bounded per-resource ID operations. This
includes Compose `down` and project-label residual cleanup. Preserve issue
#905's scenario-independent recovery and `-v` semantics, but change its
authority source from project labels alone to the durable ownership record.

## Canonical Incumbents And Required Cross-Cutting Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| SDL and realization schemas | RAES parse/semantic validation, `interpret_provisioning_plan()`, `AptlRealization`, `DeploymentRealizationSpec`, `DeploymentNodeRealization`, and `BaseContainerSpec`. Preserve authored names/labels/relationships; do not copy these schemas into an ownership model. |
| Attempt identity | `_LabStartContext`, `_resolve_run_target()`, `AcesRunTarget`, the experiment executor's attempt identity, and existing run-ID validators. Thread the one existing attempt into backend realization and delayed observation; do not infer it from time, labels, or a child. |
| Workspace root and serialization | `canonical_lifecycle_project_root()` and `lifecycle_mutation_lock()` remain the single filesystem root and mutation guard. Reuse `utils.pathsafe` no-follow/contained operations and atomic state-writing conventions for the workspace identity and ownership receipt. |
| Config identity | Strict `AptlConfig` / `DeploymentConfig` (`extra="forbid"`) and `validate_compose_project_name()`. Keep `project_name` as validated logical input and derive the bounded effective backend namespace in one canonical helper. Do not add an env/CLI naming override. |
| Backend authority | `DeploymentBackend`, `DockerComposeBackend`, `SSHComposeBackend`, `_run()`/`_run_with_input()`, and `_docker_endpoint_binding.py`. Every ownership receipt binds to the selected endpoint/daemon; RAES, CLI, API, and verifier code do not issue raw Docker commands. |
| Runtime queries and interaction | `_compose_queries.py`, `_compose_project_inventory.py`, `_compose_runtime_inventory.py`, `_compose_base_substrate.py`, `_compose_network_realization.py`, `_compose_autoremove.py`, and the provider/readiness helpers. Centralize name-to-owned-ID resolution here rather than repeating label checks at every caller. |
| Child conformance | `docker_authority_admissions()`, `deployment_spawn_image_requirements()`, `_correlated_child_ids()`, exact repo-digest/image-ID verification, mount/authority observation, and `_compose_child_lifecycle.py`. Add backend ownership before, not instead of, image/label/count/deadline checks. |
| Cleanup | `_compose_stop.py`, `_compose_lifecycle.py`, `_compose_project_cleanup.py`, `_compose_volume_cleanup.py`, network cleanup, and failed-create rollback. They remain one lifecycle workflow but consume verified receipts/IDs and never daemon-wide prune or broad name matches. |
| Results and errors | `BackendObservationError`, `BackendTimeoutError`, existing bounded backend errors, `Diagnostic`/`ApplyResult`, `LabResult`, `StartupOutcome`, and `StartupDiagnostic`. A stable resource-conflict diagnostic fits these envelopes; do not add a parallel exception hierarchy or public response DTO. |
| Logging and redaction | `get_logger()` and `redact()` remain canonical. Log safe stage, resource kind, shortened native/owner correlation, counts, and stable reason codes. Never log raw inspect JSON, Docker stderr, command lines, environment values, credentials, or host paths. |
| API and UI | Existing `verify_token`, BFF Host/CSRF/session middleware, strict API response models, terminal gates, CLI selection, and web single-flight behavior remain unchanged. Ownership enforcement is core/backend policy, not an API-only authorization check. |
| Workflow gates | `.ground-control.yaml`, `.gc/plan-rules.md`, focused pytest suites, full `pytest`, and `pre-commit run --all-files`. Compose/config/Dockerfile changes retain the clean isolated-lab validation requirement. |

## Security And Validation Passage

The intended design must pass every layer below; a matching label at a later
layer does not compensate for a missing earlier proof.

| Layer | Required passage |
| --- | --- |
| RAES schema and semantic gate | Parse and validate authored node/runtime/authority/template identities without adding backend tokens or silently renaming exact identities. Open backend choices remain explicit realization choices. |
| APTL admission/lowering | Reuse the compiled graph and exact child-image requirements. Reject a requested exact runtime/native identity when the selected namespace cannot preserve it. Ownership metadata never becomes portable desired state. |
| Strict config shape | `DeploymentConfig.project_name` passes its current validator. Workspace and attempt authority are generated control state, not pack fields, `.env` values, or untyped config additions. Invalid durable identity state blocks mutation and cleanup. |
| Filesystem state | Resolve the canonical project root once; use contained no-follow opens, owner-only permissions, bounded strict/versioned JSON, atomic create/replace, and durable publication. The record contains non-secret opaque IDs only and is distinct from immutable run evidence. |
| Daemon/transport binding | Bind and revalidate the Docker socket inode and daemon ID where local authority is required; bind remote operations to the validated SSH provider identity. A changed/unavailable daemon invalidates the receipt instead of redirecting cleanup. |
| Native object resolution | Candidate discovery is workspace/effective-project scoped, then fresh inspect verifies owner tuple, semantic binding, type, expected image where relevant, and recorded native ID. Empty/malformed/failed inspection is an error, not absence. |
| Mutation and observation | Use the verified ID for create follow-up, attach/detach, exec, copy, logs, file read, restart, wait, stop, kill, and remove. If the ID disappears, fail/observe absence without retrying by name. Child operations additionally require exact attempt ownership. |
| OS/process exposure | Keep list-form bounded subprocess argv and stdin payload seams. Opaque non-secret IDs may appear in Docker argv; credentials and environment values do not. Preserve owner-only generated env files, loopback exposure, and the existing socket/capability policy. |
| Error envelope | Reduce conflicts, uncertain ownership, endpoint changes, and residuals to stable bounded diagnostics before `LabResult`, API JSON, CLI text, logs, or persisted evidence. Raw backend output and inspect payloads never cross the envelope. |
| Authentication surface | Existing API bearer verification and BFF Host/CSRF/session gates continue to guard lifecycle and terminal routes. They authorize the caller to request an operation; the backend ownership chain separately authorizes the target resource. |

This change needs no secret, credential source, network listener, public API
field, or new environment variable. Workspace/attempt identifiers are
non-secret correlation values, not bearer tokens. A workload with daemon-root
authority can forge labels, which is why isolated daemon ownership is required
where that workload creates children and no stronger provenance is available.

## Extensibility Seam And Whole-Repository Scope

The seam is one backend-private ownership scope parameterized by:

`(canonical workspace identity, validated logical project, effective provider
namespace, bound daemon identity, current attempt identity)`

It resolves existing semantic node/template addresses to provider-native
resource IDs and emits durable lifecycle receipts. A future Docker context,
podman/libvirt provider, classroom namespace, or per-attempt daemon supplies
its own namespace and immutable native identity behind this seam. It does not
change RAES identities, widen the Docker label predicate, or require edits to
every realization DTO. Delayed verification and teardown receive the same
scope/receipt explicitly or recover it from checked lifecycle state; they do
not inherit mutable private attributes from a reused backend instance.

The whole-repository audit surface includes:

- `src/aptl/core/config.py`, `lab.py`, `lifecycle_guard.py`, `runstore.py`,
  `lab_types.py`, `utils/pathsafe.py`, and `utils/redaction.py`;
- the deployment protocol and container-ops protocol, Docker/SSH backend
  construction, endpoint binding, checked project/runtime inventory, generic
  base substrate, Compose model/name generation, network/volume realization,
  queries, health/readiness, content/account/provider exec, capture apparatus,
  snapshots, autoremove, stop/kill/rollback, and residual cleanup;
- RAES admission, realization lowering, `AcesRunTarget`, runtime-orchestration
  admissions, child observation/deadline enforcement, delayed live-gate
  verification, and realization observation/evidence envelopes;
- CLI container/lab/kill commands, API auth/BFF/lab/kill/terminal routes and
  schemas, and web lifecycle single-flight behavior;
- `.aptl/lifecycle`, `.aptl/realization`, run/capture active-state references,
  Docker socket or SSH transport, daemon IDs, Compose projects, container IDs,
  networks, volumes, host publications, and isolated-daemon fixtures;
- focused base-substrate, runtime-orchestration, deployment cleanup,
  lifecycle, CLI/API, snapshot, and real isolated-daemon tests, plus the
  repository-wide workflow gates.

The next reasonable variation is a different isolation provider. Keep the
namespace/daemon binding and native-ID adapter parameterized; do not hard-code
a Docker label name into core admission or make a second Compose-only
ownership schema.

## Gotchas And Anti-Patterns

- `com.docker.compose.project`, `aptl.lifecycle.project`,
  `aptl.node.address`, the authored child label, image identity, and running
  state are useful predicates. No subset of them is ownership.
- A lifecycle lock protects one workspace path only. It does not prevent a
  different workspace using the same default Compose project on the same
  daemon.
- `container_exists(name)` followed by any name-based action is a TOCTOU gap.
  So is inspect-by-name, then delete-by-name.
- Do not treat inspect failure as missing, or missing as permission to remove a
  same-name object. Preserve `absent`, `foreign/conflict`, `owned stale`, and
  `observation failed` as distinct internal outcomes.
- Do not put a workspace hash into SDL node names, hostnames, authored labels,
  relationship endpoints, snapshots, or evidence as though it were semantic
  identity. Scope only backend implementation names and retain aliases.
- Do not ask authors/operators to make node names, child labels, or project
  names globally unique. The backend owns collision isolation.
- Do not inject a hidden child label into an exact/closed scenario merely
  because Docker supports labels. A socket holder can observe/forge it anyway.
- Do not infer child ownership from creation time, event order, image+label,
  expected count, parent name, or the fact that only one matching child is
  currently visible.
- Do not bulk-remove label-query results, run daemon-wide prune, or use a
  foreign object as a blocker to justify broader cleanup.
- Do not persist raw Docker inspect documents or mutable ownership state in a
  sealed run archive. Do not silently recreate a lost/corrupt ownership
  receipt; that would manufacture cleanup authority.
- Do not conflate APTL run/attempt identity with the internal workflow run ID,
  the Compose project, the workspace, or a scenario address.
- Do not weaken PR #959's exact image, count, socket-propagation, or deadline
  checks. Ownership is an additional prerequisite.

## Non-Goals And Implementation Boundaries

- No RAES/LilRAE schema change, scenario rewrite, global-name requirement, or
  change to authored node/hostname/label/relationship semantics.
- No general multi-tenant authorization service, distributed lease manager,
  Kubernetes-style controller, or new workflow engine.
- No claim that Docker labels resist a malicious daemon administrator or a
  workload already holding daemon-root authority. Use daemon isolation for
  that boundary.
- No new public API, UI state machine, secret source, environment override,
  exception hierarchy, run-evidence schema, or duplicate deployment DTO.
- No automatic deletion/adoption of pre-existing foreign or uncertain
  resources, and no compatibility fallback to the current name-only cleanup.
- No redesign of image admission, artifact availability, network policy,
  host-port policy, readiness, account/content realization, capture, or
  archival beyond making their native resource interactions ownership-safe.
- No requirement to support raw-socket child orchestration on a shared daemon
  when a faithful isolated realization is unavailable; the correct result is
  a pre-mutation backend materialization conflict.

## Proof Obligations

Tests must prove the boundary against a real isolated Docker daemon, not only
mock command ordering:

- two workspaces and two attempts realize identical authored node names,
  hostnames, child-template images, and authored labels without cross-adoption;
- same-name foreign containers with the same image, a different image, and a
  stopped state are neither reused nor removed; inspection/parse/transport
  errors fail closed;
- replacement between candidate inspection and action cannot redirect reuse,
  exec, copy, attach, observation, stop, kill, or removal to the replacement;
- same-image/same-label children from another workspace or attempt never enter
  count, observation, wait, or deadline termination;
- normal stop, failed-start rollback, autoremove, clean boot, emergency stop,
  and interrupted-run recovery affect only receipt-owned native resources and
  report uncertain/residual state honestly;
- Compose-managed and directly materialized routes preserve SDL hostname,
  aliases, labels, relationships, image checks, child lifecycle, and snapshot
  identity while external implementation names are scoped;
- an exact identity or child-ownership requirement that cannot be faithfully
  isolated fails before Docker mutation with the same bounded core/API/CLI
  result, and no foreign object changes.
