# Issue #956 SDL Runtime Authority Containment Preflight

This note fixes the repository-wide boundary for faithfully realizing SDL
runtime authority without exposing APTL's host or control plane. It is
architecture guidance, not an implementation plan. The issue is authoritative;
RAES owns SDL meaning, including open, closed, exact, and constrained
realization semantics.

This note corrects the earlier policy-intersection framing in the issue #962
review and proposed ADR-055. ADR-055 remains proposed and is not amended or
accepted here. Operator configuration selects and authorizes an execution
target; it does not remove, narrow, or replace valid SDL requirements. A target
that cannot contain a faithful realization reports unsupported materialization
before mutation. The scenario is not thereby unsafe or invalid.

It also narrows the issue #949 preflight's `soc`, no-published-port,
no-participant-service, no-joined-netns, and unprivileged-holder rules. Those
rules describe the only raw-socket shape that the current shared local Docker
implementation attempted to support. They are not universal restrictions on
scenario content. Preserve #949's exact authority joins, immutable child-image
identity, daemon binding, observation, and lifecycle machinery.

## Implemented Backend Boundary

The local `docker-compose` provider is a shared-daemon profile. It continues to
realize ordinary container configuration, but it rejects host bind mounts,
raw-Docker authorities, privileged mode, capability additions, devices,
security-profile changes, and host-like namespace/runtime controls before
creating workspace state or Docker resources. The diagnostic uses
`aptl.provisioner.runtime-materialization-unsupported` and identifies the
compiled node, portable field, `shared-docker` profile, and limitation.

`ssh-compose` accepts a strict runtime-authority policy file, but it does not
currently advertise a contained high-authority profile. A remote transport,
matching daemon ID, and empty daemon inventory prove endpoint identity and
current resource occupancy only; they do not prove a guest/hypervisor boundary.
The backend therefore remains `shared-docker` and reports privileged, host-bind,
device, host-namespace, and raw-socket contracts as unsupported. A future
provider may claim high authority only by carrying independent boundary
attestation and negative-probe evidence for the exact target profile.

`deployment.runtime_authority_policy` is a project-contained relative path; the
loader does not follow symlinks, rejects unknown or malformed fields, and treats
an absent pointer as zero grants. The configured SSH target must be remote and
non-loopback. The backend verifies its daemon identity and rejects foreign
container, volume, or custom-network inventory before binding it, then
re-attests the daemon ID at later authority boundaries. These checks are
necessary endpoint/ownership evidence, never containment evidence.

For any future contained raw-socket profile, qualification additionally requires an exact grant
over the immutable pack id, pack version and pack-set digest, component address,
authority id, canonical target socket, and image-template set. A delegated
template set may only narrow that set. The grant does not filter runtime fields
or prove realization; native container readback independently corroborates the
effective privileges, capabilities, security options, namespace modes, devices,
mounts, runtime selection, DNS/host/group configuration, logging, init, and
read-only root state.

The current Compose profile reports unsupported materialization for masked and
read-only path lists, publish-all-ports, custom init contracts, process-scoped
capability requirements, and joined network namespaces whose owner cannot yet
be independently read back. The generic substrate reports unsupported for
container-security fields and non-volume mounts it cannot faithfully lower. No
field is stripped or substituted.

## Architecture Decisions And Boundaries

### Qualify one complete runtime contract before any mutation

The admission chain remains:

`SDL -> RAES parse/semantics/compile/plan -> interpret_provisioning_plan() ->
DeploymentRealizationSpec -> selected DeploymentBackend -> native readback`

RAES models and the admitted plan are the only source of authored meaning.
APTL must not duplicate the runtime schema, infer authority from Compose, or
turn an omitted field into a closed value. Use the plan's realization authority
and explicitness for open/closed decisions; Pydantic defaults and field presence
on a reconstructed `RuntimeConfiguration` are not an explicitness oracle.

The selected backend performs one graph-wide, read-only qualification over both
image-backed and generic-substrate nodes. It must account for the complete
effective authority of each node and of authority joins between nodes:

- `privileged`, seccomp/AppArmor and other security options;
- capability additions and drops, including backend-added init mechanics;
- PID, IPC, network, user, cgroup, and other namespace choices or joins;
- devices and device permissions;
- bind, volume, tmpfs, generated-artifact, control-interface, and implicit
  substrate mounts, including source identity and access mode;
- host publications, egress, shared networks, and management reachability;
- orchestration control interfaces, reachable daemon authority, spawned
  workloads, and their ownership/lifecycle closure; and
- selected image/substrate, OS/distribution, architecture, init, resource, and
  process defaults that contribute to effective runtime authority.

Qualification happens after semantic planning and target selection but before
workspace receipts, generated deployment files, image pull/build, volume or
network creation, generic-node start, or Compose mutation. Read-only target
probes are allowed. Qualification may render into an isolated, disposable
temporary area, but it must not publish files under the project realization or
lifecycle roots. It receives the already admitted logical workspace/attempt
identity; it must not mint a durable ownership receipt merely to decide whether
the target is supportable. This ordering must move ahead of the current mixed
path, which can materialize image-free nodes before validating the Compose half,
and ahead of any path that validates only the rendered image-backed model.

Component materialization specifications are inspected read-only for planning.
Their Docker builds are deferred until the admitted graph and effective Compose
models have passed this qualification. The resulting digest is then installed
into the same execution plan's availability evidence before apply; the scenario
is not replanned.

A failure uses the existing RAES `Diagnostic` -> `ApplyResult` ->
`render_raes_diagnostics()` -> `LabResult`/startup envelope. It names a safe
compiled node address, portable field/requirement, selected backend profile,
and concrete limitation. Use the existing `aptl.provisioner.*` diagnostic
namespace and redaction boundary; do not raise `UnauthorizedCapabilityError`,
call the scenario unsafe, or add another exception hierarchy.

### Separate scenario authority, target authorization, and containment

These are three different decisions:

| Decision | Authority | Meaning |
| --- | --- | --- |
| Scenario desired state | RAES SDL and admitted plan | What must exist in-world; exact/closed values are unchanged, while open or constrained values permit only the choices RAES semantics allow. |
| Execution target selection | Strict APTL deployment configuration | Which host, guest, daemon, device mapping, storage root, and containment profile APTL may use. Scenario content cannot choose or discover these resources. |
| Materialization qualification | Selected backend plus native probes | Whether that target can realize the complete desired state and keep physical-host, APTL-control, credential, and other-workspace resources out of the scenario's authority closure. |

An operator selection is necessary authority to use a target, not permission to
reinterpret the scenario. Conversely, SDL `privileged`, a bind source, device,
namespace join, or control interface cannot select an operator host resource.
Resolve such values only inside the selected containment domain or through an
explicit APTL-configured target binding. If the exact meaning cannot be
preserved there, fail unsupported before mutation.

Keep target/profile selection in the existing strict `DeploymentConfig` and
`get_backend()` seam. Any new provider-specific locator is bounded, validated,
non-secret configuration; credentials continue through existing credential
sources. Do not add per-field allow/deny grants, scenario-name exceptions,
environment-variable backdoors, or a second policy service. A future backend
or containment mechanism enters through the same `DeploymentBackend` seam and
must publish and prove its own capability envelope.

### The containment domain, not a field allowlist, protects APTL

Faithful privileged or unconfined execution cannot be contained from a
same-kernel host merely by checking its Compose fields. The claimed profile
must provide a boundary appropriate to the strongest admitted authority. For a
profile that supports `privileged`, unconfined seccomp, host-like namespaces,
devices, or raw orchestration authority, compromise of every in-world workload
must still not yield:

- the physical host or an APTL management/control process;
- APTL source, generated credentials, API/session/model credentials, SSH keys,
  run archives, or evaluator-only state;
- the daemon or native resources used by APTL or another workspace/attempt; or
- undeclared physical devices, mounts, management networks, or outbound routes.

Container labels, Compose profiles, rootless mode, user namespaces, socket
mount access mode, absent host publications, and network membership may be
useful mechanisms or evidence, but none alone proves this boundary. Support for
the strongest contracts generally requires a disposable guest/microVM or an
equivalently qualified isolation boundary with the APTL controller outside the
scenario's authority closure. A nested or isolated daemon is sufficient only
for requirements that cannot escape its kernel and storage boundary.

A raw Docker socket grants broad authority over the selected daemon. When SDL
requires it, the socket presented in-world must address a scenario-owned daemon
inside the qualified containment domain, never APTL's management daemon. The
holder may create workloads outside authored image/label conventions; #949's
image/count/label checks are observation and semantic-correlation evidence, not
an enforcement sandbox. A broker is supportable only if its API can realize
every authored operation and shared-network behavior; otherwise it changes the
contract and must be rejected.

Shared networks are valid scenario topology. Authority holders and spawned
children may share them when authored, but the network implementation must be
inside the same containment/ownership domain and must not bridge to APTL
management or another workspace. The current `soc` profile and
tests of management-only shapes are not containment evidence and must not be used
to reject a scenario that a stronger target can realize.

### Preserve authored state; distinguish backend choices and mechanics

Image-backed `_container_config()` already lowers `privileged`,
`security_opt`, capabilities, and one network-namespace join. The generic
substrate currently has a separate capability allowlist, fixed host-cgroup and
unconfined init requirements, partial mount lowering, and no equivalent full
container-policy lowering. Neither route defines SDL support by itself.

One qualification decision covers both routes before dispatch. Exact or closed
authored values pass through unchanged on a supporting target. Backend choices
for semantically open or underspecified requirements, such as choosing a Linux
distribution or an init implementation, use the existing realization-authority
and backend-implementation-profile machinery, are recorded as backend choices,
and receive native readback. Backend mechanics may not add authority behind an
exact/closed declaration. In particular:

- `_ALLOWED_EXTRA_CAPABILITIES` is an implementation limitation to replace with
  target qualification, not authority to ban otherwise valid capabilities;
- `_INIT_CAPABILITY_BASELINE` and the cgroup-mount baseline cannot make
  undeclared excess disappear. They are acceptable only where RAES semantics
  authorize the backend choice and readback identifies it as such; and
- unsupported bind/tmpfs/device/namespace behavior must fail before either
  route mutates state, never be dropped because one renderer lacks a field.

Do not rewrite authored content to fit Compose, require an open scope, inject a
safer value, or use an operator grant as a substitute value. If RAES lacks a
portable concern/readback path for a required field, fix or extend the upstream
contract before claiming semantic support; a local duplicate concern schema or
an `ApplyResult.details` assertion must not bypass the realization gate.

### Readback proves realization and containment independently

Successful support requires two independent evidence classes:

1. Native realization readback proves the effective container/guest state
   matches the authored requirement or authorized backend choice: inspect/runtime
   state for capabilities, security profiles, namespaces, devices, mounts,
   daemon endpoint/identity, networks, images, and lifecycle.
2. Containment evidence proves attempted reachability from a fully compromised
   scenario workload stops at the selected boundary and cannot access APTL
   control resources, credentials, the physical host, or sibling workspaces.

Extend the existing `observe_realization()`, runtime-concern observers,
`DeploymentObservationContext`, operational realization observations, #949
authority observation, and #964 native-ID ownership receipts. Planned values
are never readback. Keep raw inspect documents, command stderr, host paths,
environment values, and credentials out of snapshots and run archives; persist
only bounded safe identities, provenance, evidence digests, and verdicts
through existing evidence surfaces. Missing, malformed, stale, or
uninspectable evidence is failure, not an empty successful observation.

## Canonical Incumbents And Required Cross-Cutting Reuse

| Concern | Canonical owner and required reuse |
| --- | --- |
| SDL schema and semantics | `raes.parse_sdl_file`, RAES semantic validation/compiler/planner, plan realization authority/explicitness, and `RuntimeConfiguration`. Do not create APTL copies or infer semantics from Pydantic defaults. |
| Plan and deployment models | `interpret_provisioning_plan()`, `AptlRealization`, `DeploymentNodeRealization`, `DeploymentRealizationSpec`, and `BaseContainerSpec`. Retain authored runtime on the node and extend the existing carried #949 decision only with backend facts it actually needs; do not create a parallel node/runtime DTO. |
| Backend selection and target access | Strict `AptlConfig`/`DeploymentConfig` (`extra="forbid"`), `get_backend()`, `DeploymentBackend`, `DockerComposeBackend`, `SSHComposeBackend`, `_docker_endpoint_binding.py`, and provider-specific validators. Target location and access are operator configuration, never SDL or ambient fallback. |
| Backend choices | `raes_backend_implementation.py`, `_raes_backend_implementation_profiles.py`, `raes_operating_systems.py`, `raes_base_substrate.py`, and artifact/image availability. Use RAES OPEN authority and record selected OS/substrate/mechanics; do not turn a catalog into a content allowlist. |
| Image-backed lowering | `_compose_node_generation.py`, generated realization files, `_compose_model_realization.py`, and `docker compose config --no-interpolate --format json`. Validate the complete effective model, not a renderer fragment. |
| Generic and mixed lowering | `raes_base_substrate.py`, `_compose_base_substrate.py`, `_compose_image_free_realization.py`, and `_compose_mixed_realization.py`. Qualify the whole graph before the generic half starts; do not maintain a second privilege policy. |
| Runtime authority | `runtime_authority.py`, `raes_runtime_orchestration.py`, `_compose_runtime_orchestration.py`, `_docker_endpoint_binding.py`, `_compose_runtime_observation.py`, and `_compose_child_lifecycle.py`. Preserve exact joins, daemon/image identity, deadlines, and non-propagation checks while replacing current shape restrictions with target capability limitations. |
| Resource ownership and lifecycle | #964's `_compose_resource_ownership.py`, receipt capture/resolution, native IDs, workspace-scoped names, `canonical_lifecycle_project_root()`, and `lifecycle_mutation_lock()`. Isolation does not permit name/label-based adoption or broad cleanup. |
| Native observation | `observe_realization()`, `raes_runtime_observation.py`, `_runtime_concern_excess.py`, `_runtime_mount_observation.py`, RAES SEM-218 disclosure, and the realization envelope. No planned-state echo or baseline subtraction that hides excess authority. |
| Paths, secrets, and process execution | `utils.pathsafe`, secure/atomic generated-file writers, existing `.env` and credential-source boundaries, argv-list subprocess calls, `_subprocess_kwargs()`, and `BackendTimeoutError`. No credential or sensitive mount source in argv, logs, evidence, or diagnostics. |
| Errors and observability | `Diagnostic`, `diagnostic()`, `ApplyResult`, `render_raes_diagnostics()`, `LabResult`, startup diagnostics, `get_logger()`, and `redact()`. Preserve bounded external envelopes and safe node/field/backend detail; do not expose raw Docker output. |
| Control-plane entry points | CLI orchestration plus FastAPI router token dependencies and BFF Host/same-origin/CSRF/two-factor session gates. Every start entry point reaches the same lifecycle lock and qualification; no privileged alternate route. |
| Qualification tests | Existing runtime-orchestration, env-pack rendering, generic-substrate, resource-ownership, runtime-observation, config/API/CLI, appliance-boundary, TechVault static/live, and no-silent-host-escalation suites. Native containment claims require a real isolated target, not only mocked Docker argv. |

## Security And Validation Passage

| Layer | Required passage |
| --- | --- |
| CLI/API authorization | Existing CLI ownership and authenticated API start routes remain the only control entries. API token, Host, strict same-origin/CSRF, session-cookie-plus-header, and lifecycle-lock checks are unchanged and cannot be bypassed by a new backend/profile. |
| RAES shape and semantic validation | Parser/compiler/planner validates the SDL and joins. APTL consumes full UIDs/addresses, runtime values, constraints, and explicitness; it adds no content policy and does not locally redefine valid values. |
| Strict config shape | `AptlConfig`/`DeploymentConfig` validates provider and target/profile selection with `extra="forbid"`. Host/daemon/device/storage locators are bounded and explicit; unknown fields fail. Secrets remain credential-source references rather than stored values. |
| Whole-graph materialization qualification | The selected backend evaluates image-backed and generic nodes, cross-node namespace/network/orchestration joins, and backend mechanics together. Failure is read-only and names the node/field/profile limitation before any deployment write or daemon mutation. |
| Host path/device/daemon boundary | Scenario paths and device names resolve only within the selected containment/binding map. Socket/daemon identity is pinned and revalidated. No ambient `DOCKER_HOST`, Docker context, host root bind, physical device, APTL directory, or sibling workspace is reachable unless target configuration explicitly selects it and containment still holds. |
| Effective model gate | In-memory/contained rendering plus Compose/native validation proves exact fields survived lowering. It compares both routes against the same qualification and refuses dropped, substituted, or extra state. Secret interpolation remains disabled during model inspection. |
| Native realization gate | Host/hypervisor/daemon-side readback corroborates privileges, security profiles, capabilities, namespaces, devices, mounts, networking, images, daemon authority, and lifecycle. Missing evidence cannot be replaced by the planned value. |
| Containment/escape gate | Negative live probes from privileged, unconfined, raw-socket, and shared-network workloads cannot access host/control credentials, management daemon/resources, or another workspace. Boundary identity and probe results are versioned evidence for the exact backend/host profile. |
| Error/log/evidence envelope | Only bounded safe identifiers and stable diagnostics cross outward. `redact()` remains mandatory for logs/serialization; raw inspect, subprocess output, environment, tokens, keys, and sensitive host paths do not enter API responses, `ApplyResult.details`, snapshots, or archives. |

## Extensibility Seam

The seam belongs at the selected `DeploymentBackend` and is parameterized by
the admitted `DeploymentRealizationSpec`, RAES realization authority, selected
target/profile identity, target-native capability facts, offline policy,
logical workspace/attempt identity (without creating ownership state), and
requested observation strength. It produces a read-only qualification result
plus a containment binding used unchanged by lowering, start, observation, and
cleanup. Durable ownership receipts and generated realization artifacts are
created only after that result succeeds.

The next backend, rootless profile, microVM implementation, non-Docker engine,
device mapping, or narrower orchestration broker adds a separate qualified
profile at this seam. It must not widen a global allowlist, add product-name
branches, or change the portable SDL. Capability claims are versioned against
the actual host/runtime/architecture and qualification evidence; they are not
inherited because another profile passed.

## Gotchas And Anti-Patterns

- Do not implement `authored requirements ∩ operator allowlist`. A denied or
  unsupported exact value is a backend materialization failure, not a modified
  realization.
- Do not use `_ALLOWED_EXTRA_CAPABILITIES`, `soc`, image names, service names,
  scenario IDs, absent ports, or network labels as scenario-validity policy.
- Do not strip `privileged`, replace `seccomp:unconfined`, reduce capabilities,
  force private namespaces, turn a bind read-only, remap a device, or require an
  author to open a scope.
- Do not qualify only `_container_config()` or only the generic substrate. Mixed
  graphs and cross-node joins are one authority closure.
- Do not validate after image-free nodes, networks, volumes, generated files,
  images, or Compose services have already been mutated.
- Do not treat rootless Docker, user namespaces, read-only Docker socket mounts,
  loopback publishing, or an isolated bridge as proof against daemon or kernel
  authority.
- Do not give a raw-socket holder APTL's management daemon. Image/label/count
  checks cannot constrain what that holder creates.
- Do not inject opaque ownership labels into an exact/closed child contract as a
  substitute for daemon/guest isolation; a daemon administrator can forge them.
- Do not subtract backend-added capabilities or mounts from excess detection
  unless the admitted open semantics authorized that exact backend choice.
- Do not resolve scenario bind/device paths against the controller cwd, project
  checkout, `/`, ambient Docker host, or another workspace.
- Do not log constructed commands containing secrets or place env values,
  credentials, sensitive bindings, or raw native documents in diagnostics.
- Do not claim containment from mock tests, static Compose output, a successful
  boot, or self-reported in-guest evidence. Use independent native readback and
  adversarial live probes.

## Non-Goals And Implementation Boundaries

- No RAES/LilRAE semantic fork, APTL-local SDL schema, content allowlist,
  organizational policy service, or per-scenario exception registry.
- No requirement that the current shared local Docker backend support every
  valid SDL contract. Honest pre-mutation unsupported materialization is valid.
- No promise that a container-only boundary can contain privileged or
  unconfined workloads. Support claims follow measured target capabilities.
- No redesign of #949 authority joins/image/lifecycle observation, #964 resource
  ownership, scenario verification, participant execution, or run archival.
- No new public API route, auth scheme, secret source, exception hierarchy,
  workflow engine, node DTO, or persistence store.
- No automatic access to the physical host, operator daemon, devices,
  credentials, source tree, or other workspaces because SDL names a similar
  resource; configuration selects targets and containment remains mandatory.
- No acceptance of existing host exposure as TechVault parity. Regression proof
  preserves SDL-defined vulnerable behavior inside the scenario while removing
  out-of-world reachability.

## Proof Obligations

Tests must distinguish successful contained realization, unsupported
materialization, and attempted escape. At minimum they cover:

- image-backed, image-free, and mixed nodes with exact/closed and open or
  underspecified authority, including backend-selected Linux distribution;
- privileged, unconfined seccomp, capability add/drop, every supported
  namespace form, devices, bind/volume/tmpfs mounts, and combinations thereof;
- raw-socket holders that create undeclared children and share authored networks,
  while the socket reaches only the scenario daemon;
- foreign/sibling workspace resources, APTL control containers, project files,
  credentials, API/model/SSH secrets, the physical host, and management networks
  remaining unreachable from a fully compromised workload;
- precise pre-mutation diagnostics for each unsupported node/field/backend, with
  no partial generic or Compose realization and no generated secret leakage;
- independent native readback of effective authority plus containment evidence,
  including failure, interruption, teardown, and stale-evidence cases; and
- TechVault and deliberately vulnerable scenarios retaining authored behavior
  on a qualified target, without treating former host exposure as parity.

Mock/unit tests remain useful for ordering, field preservation, diagnostic
shape, and redaction. Backend support claims require live qualification on each
advertised host/runtime/architecture profile and must be withdrawn or narrowed
when that evidence no longer passes.
