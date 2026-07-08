# ADR-046: Dynamic ACES Scenario Realization

## Status

accepted

## Date

2026-06-29

## Context

ADR-035 adopted ACES SDL as APTL's scenario authoring surface and wired APTL in
as a conformant ACES backend target. Under that decision the ACES runtime stack
compiles an authored SDL document into a typed `RuntimeModel`, plans a composite
`ExecutionPlan` (provisioning, orchestration, evaluation), and applies it
against APTL's registered `RuntimeTarget`.

ADR-035 also drew a Parity Inventory Boundary that named `docker-compose.yml`
and the `DeploymentBackend` inventory methods as the canonical source for
topology, profiles, networks, static IPs, hostnames, volumes, health checks,
published ports, and service dependencies. That framing was correct for the
cutover: APTL realized one scenario (TechVault), and the compose file was both
the realization vehicle and the de facto topology authority.

That framing no longer holds. APTL now realizes a compiled ACES `ExecutionPlan`
whose `RuntimeModel` carries networks, node deployments, feature bindings,
content placements, account placements, and, per SEM-218, typed realization
requirements. The compiled scenario, not the static compose file, decides what
the range contains. The compose file remains the realization vehicle, reached
through a profile index, but it is no longer the source of truth for topology.

The compiler emits these surfaces on `RuntimeModel`
(`aces_processor/models.py`): networks, node deployments, feature bindings,
content placements, account placements, and `realization_requirements`
(`models.py:4264`). The last field is the SEM-218 contract: a tuple of
`CompiledRealizationRequirement`, each carrying an `ExplicitnessClass` of
`EXACT`, `CONSTRAINED`, or `OPEN` (`aces_processor/semantics/realization.py`).
`EXACT` means the authored value must be honored precisely; `OPEN` is the
open-taxonomy sentinel that a backend may satisfy loosely. The planner gates
the manifest's declared realization support against each requirement through
`realization_support_diagnostics` (`aces_processor/planner.py:957`).

APTL must turn that compiled plan into a running range without reintroducing a
second topology authority, a second SDL, a duplicate compose parser, or raw
Docker calls. The owners that already exist are the ones this decision builds
on, not new abstractions.

## Decision

APTL realizes a compiled ACES `ExecutionPlan` dynamically through an
**interpret-then-driver** pattern. The compiled `RuntimeModel` is the
authoritative interpretation input; `docker-compose.yml` is the realization
vehicle selected by profile, not the topology authority.

Two stages compose the realization:

- **Interpret.** `interpret_provisioning_plan`
  (`src/aptl/backends/aces_realization.py:56`) translates the `ProvisioningPlan`
  carried on the `ExecutionPlan` into a typed `AptlRealization`
  (`src/aptl/backends/aces_realization_model.py:77`). Nodes become
  `NodeRealization`, networks become `NetworkRealization`, and feature
  bindings, content placements, and account placements become
  `PlacementRealization`. The interpreter recognizes the resource types in
  `SUPPORTED_RESOURCE_TYPES` (`src/aptl/backends/aces_diagnostics.py:12`):
  network, node, feature-binding, content-placement, and account-placement. An
  unsupported resource type produces a diagnostic rather than a hard failure, so
  a richer authored scenario degrades visibly instead of crashing the apply.

- **Driver.** `select_backend_profiles`
  (`src/aptl/backends/aces_profiles.py:205`) and `ComposeProfileIndex`
  (`src/aptl/backends/aces_profiles.py:31`) map the interpreted realization onto
  the ordered set of Docker Compose profiles to start, including the profile
  dependency closure. `AptlProvisioner.apply`
  (`src/aptl/backends/aces.py:335`) chains the two stages: interpret the plan,
  select the profiles, then drive `DeploymentBackend.start_lab`.

All container, network, and host operations route through the
`DeploymentBackend` Protocol
(`src/aptl/core/deployment/backend.py:33`). No ACES adapter code calls raw
Docker or parses compose output directly. This binds the realization to ADR-037:
the runner boundary is the extensibility seam, not a mixin hierarchy or a
subprocess shortcut.

The realization honors SEM-218 open and closed semantics. APTL consumes
`RuntimeModel.realization_requirements` and declares its own realization support
through the `RealizationSupportDeclaration` in `create_aptl_manifest`
(`src/aptl/backends/aces_manifest.py:160`), which currently claims `CONSTRAINED`
mode for the `runtime-realization` domain. The planner's
`realization_support_diagnostics` gate decides whether that declaration
satisfies each authored requirement; APTL does not re-evaluate the requirements
with a local model.

Realization evidence persists through the existing run-record owners, not a new
record type. Selected profiles, profile dependency closure, and `AptlRealization`
details are written through `LocalRunStore`
(`src/aptl/core/runstore.py:125`) and referenced from `RangeSnapshot`
(`src/aptl/core/snapshot.py:105`), consistent with ADR-044. Durable non-secret
settings bind through strict `AptlConfig` (`src/aptl/core/config.py:182`, per
ADR-025); secret-bearing runtime values stay in `EnvVars` and `.env`
(`src/aptl/core/env.py:25`). The realization record stores digests and
non-secret identities only.

## Paper Scenario Spine Addendum

Issue #573 starts the first end-to-end dynamic realization: the paper scenario
from Brad-Edwards/aces#598. For that scenario, the profile-index driver above is
only historical compatibility for the TechVault curated variants. The paper
scenario must not be realized by selecting profiles over the fixed
`docker-compose.yml`; it must realize the topology declared by the compiled ACES
plan.

The interpret stage remains pure. It consumes `PlannedResource`s and compiled
runtime artifacts and emits portable, typed APTL realization specs: nodes,
networks, participant action contracts, observation boundaries, and evaluator
evidence surfaces. It does not call Docker, read runtime container state, branch
on a scenario name, or construct backend argv.

The driver stage is the `DeploymentBackend` boundary from ADR-037. Any new
realization operation must be a narrow typed method on `DeploymentBackend` and
implemented by both local and SSH Compose backends using their existing runner,
timeout, project-name, label-filtering, and error-envelope behavior. Do not add
a generic `docker(args)`, `host_run(args)`, or raw Compose-output parser to the
ACES adapter.

Participant action realization must be compiled-artifact driven. The existing
`DEFAULT_PARTICIPANT_ACTIONS` / `PARTICIPANT_ACTION_ADDRESS` TechVault SSH probe
is not the paper-scenario contract. The `probe-customer-portal-login` action,
its source participant, target address, command/interaction contract, success
classification, disclosed observation boundary, participant snapshot entries,
and shared-state scope must come from the compiled SDL/runtime artifacts.
Scenario identity may select the scenario file; it must not select behavior.

Wazuh evidence for the paper action is evaluator-only evidence. It may be made
available through `AptlEvaluator`, `RuntimeSnapshot`, and `LocalRunStore`, but
it must not be exposed as participant-visible task context or participant
observation-boundary content, and it must not claim detection quality. Boundary
checks must prove the participant path reaches the DMZ portal while the internal
DB and Wazuh/evaluator surfaces are absent from the participant-visible
workbench/task context.

Non-secret realization knobs continue to bind through strict `AptlConfig`
(ADR-025). Secret-bearing runtime values continue to bind through `EnvVars`,
`.env`, rendered config, and placeholder checks (ADR-028/ADR-029). Any
realization evidence persisted to disk must use `LocalRunStore` JSON/JSONL
writers or `RangeSnapshot.to_dict()` so path validation and redaction stay at
the existing serialization boundaries.

The extensibility parameter is the typed realization spec, not the paper
scenario name. Future scenarios should be able to vary participant source node,
target service, network boundary, evaluator-only evidence source, and backend
project name without editing a paper-scenario branch.

## Image Realization Addendum

Issue #574 realizes node images from ACES `source` and captured
`source.build` provenance. This is part of the same dynamic realization
boundary as nodes and networks; it is not a Compose-profile aliasing feature.

APTL consumes the ACES `Source` and `ContainerImageBuildProvenance` schemas as
compiled into each node resource payload under `spec.node.source`. Do not define
an APTL-local source, image, Dockerfile, layer, or build-provenance schema. The
interpreter may extract the ACES payload into APTL's typed realization output,
but the source of truth remains the ACES parser/compiler and the backend-facing
`ProvisioningPlan`.

Image realization has two valid outcomes:

- **Pull.** A node `source` resolves through an APTL image policy and resolver
  to a pullable image reference. Digest-pinned references are preferred and are
  the identity recorded in run evidence when available.
- **Build.** A node `source.build` carries enough captured provenance to build a
  local image through the deployment backend. Build provenance is evidence and
  input to a typed build operation; raw Docker history text and layer metadata
  must not be treated as shell script. If the provenance is insufficient to
  construct a safe build context and instruction stream, realization rejects
  with a diagnostic.

The image trust policy is enforced at the realization boundary before any pull,
build, tag, or compose start can use the image. Policy is a non-secret
first-party concern: if it becomes configurable, it belongs in strict
`AptlConfig`; otherwise it may be a narrow code-owned policy object passed into
the interpreter/driver seam. It must not be hidden in `.env`, Compose labels, a
scenario-name branch, or a backend-specific allowlist.

All image side effects route through `DeploymentBackend`. APTL adapter code may
extend `DeploymentRealizationSpec` and add narrow typed backend operations, but
it must not call `docker pull`, `docker build`, `docker tag`, or
`docker compose` directly. Docker Compose and SSH Compose must share the same
runner, timeout, project-name, logging, redaction, and error-envelope behavior
defined by ADR-037.

Rejection is a structured diagnostic, not a raw backend error. Diagnostics may
name the node address, policy reason code, and non-secret policy rule id, but
must not echo an untrusted image reference, build arg value, registry
credential, rendered Dockerfile text, raw backend stderr, or `.env` value. Use
the existing `aptl.backends.aces_diagnostics.diagnostic()` and
`render_aces_diagnostics()` path so redaction and ACES operation-status
contracts stay intact.

Realization evidence is non-secret identity and provenance only: resolved image
digest/ref, pull-or-build mode, source name/version, provenance references,
instruction/layer digests when safe, and policy decision metadata. Persist it
through `AptlRealization.details()`, `ApplyResult.details`, `LocalRunStore`, and
`RangeSnapshot.to_dict()` as appropriate. Do not create a second run record or
store registry credentials, build secrets, raw environment values, or rendered
secret-bearing config.

## Network Realization Addendum

Issue #575 realizes networks and node attachments from the compiled ACES
provisioning plan. The source of truth is `NetworkRealization` plus each
realized node's infrastructure links and declared static addresses; the
hand-authored `docker-compose.yml` networks are only compatibility input for
curated/profile-backed scenarios.

Network side effects are backend responsibilities. The APTL ACES adapter may
extend `DeploymentRealizationSpec` with a narrow typed attachment shape when
the existing node/network tuples cannot preserve the authored
network-to-address relationship, but it must not create a second SDL model, a
second Compose topology parser, or an argv passthrough. Docker Compose and SSH
Compose must implement the same typed backend operation through their existing
runner, timeout, project-name, label-filtering, logging, redaction, and
`LabResult` / `BackendTimeoutError` behavior.

The backend must materialize each declared network with the authored CIDR,
gateway, and `internal` flag when those values are present. `internal: true`
maps to Docker's internal network semantics and is the dynamic-scenario parity
for SAF-002. An authored `internal: false` is an explicit egress-allowed
network; an omitted value is backend default and must not be silently converted
into egress allowed when SEM-218 marks the concern exact or constrained. Docker
network names must remain project-scoped and collision-resistant, and
backend-created networks must carry the same project label used by
`host_list_lab_networks()` so snapshots and cleanup do not leak across shared
daemons.

Static addresses are per attachment, not per node. Flattening
`static_addresses` loses which network owns which address and breaks
multi-homed nodes such as `wazuh-manager`, `suricata`, `dns`, `webapp`, and
`kali`. The typed deployment input must preserve `(node, network, address)`
provenance so the backend can call `docker network connect --ip ...` (or the
provider equivalent), participant binding can resolve service hosts from the
realized topology instead of stale Compose IPs, and run evidence can explain
which authored link produced each address.

APTL relies on ACES parser/compiler validation for SDL shape and SEM-218
explicitness. Backend-side validation is limited to provider safety and
faithful realization: parse CIDRs, gateways, and static IPs with typed IP
parsers; reject gateways or static addresses outside their declared network;
reject duplicate addresses on a network; reject ambiguous normalized network
names; and fail before side effects when an exact authored value cannot be
honored. Rejections are ACES diagnostics via
`aptl.backends.aces_diagnostics.diagnostic()` / `render_aces_diagnostics()`,
not raw Docker stderr, a new exception hierarchy, or English output scraping.

Network realization evidence is non-secret topology data: authored network
address, backend network name, CIDR, gateway, internal flag, node attachment,
static IP, selected backend, and non-secret provenance rule. Persist it through
`AptlRealization.details()`, `ApplyResult.details`, `LocalRunStore`, and
`RangeSnapshot.to_dict()` as appropriate. Do not store raw backend stderr,
rendered Compose overrides containing unrelated config, `.env` values, or
secret-bearing service configuration.

## Content Placement Realization Addendum

Issue #576 realizes ACES `content-placement` resources onto already-realized
containers. This is part of the dynamic realization driver, not a scenario
catalog feature and not a post-run evidence collector.

APTL consumes the ACES compiled `ContentPlacement` payload and the SDL
`Content` schema carried under each resource's `spec`. Do not define an
APTL-local content schema, content-type vocabulary, sensitivity taxonomy, or
dataset model. The interpreter may extract backend-facing fields from the ACES
payload, but the source of truth remains the ACES parser/compiler and the
`ProvisioningPlan`.

Content placement has three backend-visible forms:

- **File.** A `type: file` resource materializes file content at the authored
  `path`. Inline `text` may become file bytes. Source-backed files must resolve
  through an explicit project-contained source-materialization boundary before
  backend copy; a descriptor-only surrogate is not realization.
- **Directory.** A `type: directory` resource materializes the authored
  directory at `destination`. Empty-directory realization is still a side
  effect and must be testable.
- **Dataset.** A `type: dataset` resource materializes the authored dataset as
  real target-container content, either from source-backed material or from a
  deterministic dataset representation derived from `items` and `format`.
  Merely writing `/etc/aces/content/*.json` metadata does not satisfy APTL's
  claimed `supported_content_types`.

All side effects route through `DeploymentBackend`. Extend
`DeploymentRealizationSpec` with a narrow typed content-placement shape, and
have Docker Compose and SSH Compose realize it through their shared runner,
timeout, project-name, logging, redaction, and `LabResult` /
`BackendTimeoutError` behavior. Do not call `docker cp`, `docker exec`,
`tar`, `ssh`, or `docker compose` directly from the ACES adapter, and do not add
a generic backend argv passthrough.

Scenario-authored content is less trusted than code-defined named-volume seed
specs. The existing `seed_named_volumes` shell-copy pattern is only valid for
code-owned relpaths. Content placement must validate authored container paths
before side effects: require absolute POSIX target paths, reject empty paths,
NUL bytes, parent traversal, ambiguous directory/file targets, and unsafe
metadata-derived filename components. If a shell is unavoidable inside a
container, pass opaque content through stdin, temporary files, or an encoded
payload boundary rather than interpolating authored content or paths into shell
text.

Sensitivity is metadata and policy input, not a logging exemption. ACES
`sensitive`, SEM-218 explicitness/provenance, and APTL's ADR-029 secret classes
must stay distinct: designed vulnerable target content may be written into the
target container when authored, but control-plane/operator secrets must never be
sourced from `.env`, generated config, host private keys, registry credentials,
or operator state. Realization evidence stores non-secret identity only:
resource address, content type, target node/container, target path/destination,
source reference or digest/checksum, item count/format, sensitivity class, and
realization provenance. Persist evidence through `AptlRealization.details()`,
`ApplyResult.details`, `LocalRunStore`, and `RangeSnapshot.to_dict()`. Do not
store raw sensitive file bytes, dataset rows, source package bytes, backend
stderr, generated config, `.env` values, or rendered secret-bearing content.

Rejection is a structured ACES diagnostic, not a raw backend error. Diagnostics
may name the content resource address, target node/container, content type, and
validation reason code. They must not echo raw content text, dataset rows,
source bytes, credential-shaped values, raw backend stderr, or host paths that
reveal operator-private state. Use `aptl.backends.aces_diagnostics.diagnostic()`
and `render_aces_diagnostics()` so redaction and operation-status contracts
stay intact.

## Security Layers

| Layer | Requirement |
| --- | --- |
| ACES parser and compiler gate | Authored scenarios enter through `aces_sdl.parse_sdl_file` and compile through the ACES compiler and planner. APTL does not structurally revalidate ACES SDL or recompile the `RuntimeModel` with local models. |
| Realization requirement gate | SEM-218 open and closed semantics are enforced by the ACES planner's `realization_support_diagnostics` against APTL's `RealizationSupportDeclaration`. APTL reads `realization_requirements`; it does not re-derive explicitness classes locally. |
| Deployment boundary gate | The curated compatibility path may still drive `DeploymentBackend.start_lab` with profiles. The paper scenario drives typed `DeploymentBackend` realization methods. No ACES adapter code calls raw Docker, `docker compose`, or parses compose output directly (ADR-037). |
| Image trust gate | Node image pull/build decisions are made from ACES `Source` / `source.build` payloads and pass an APTL image policy before backend side effects. Untrusted or insufficient image inputs fail closed through ACES diagnostics without echoing raw image refs, build args, credentials, Dockerfile text, or backend stderr. |
| Network topology gate | Network creation, IPAM, `internal` egress policy, and per-node attachments come from typed realization specs. Backend validation parses CIDR/gateway/static IP values, preserves project scoping, labels backend-created networks, and fails closed before side effects when authored exact/constrained values cannot be honored. |
| Content placement gate | Files, datasets, and directories come from ACES `content-placement` resources and are materialized through typed `DeploymentBackend` operations after target-path/source validation. APTL may extract backend input from ACES payloads, but must not mirror the ACES content schema or fall back to descriptor-only records. |
| Config and env binding | Non-secret realization knobs bind through strict `AptlConfig`; runtime secrets stay in `EnvVars` and `.env`. The realization record stores digests and non-secret identities, never `.env` values, rendered config, tokens, or key material. |
| Persistence and redaction | Realization details, selected profiles for compatibility scenarios, typed realization specs for dynamic scenarios, and evaluator-only evidence enter JSON through `LocalRunStore` and `RangeSnapshot.to_dict()`, inheriting ADR-029 redaction and path-containment checks. |

## Maintainability

The canonical incumbents this decision builds on are:

- `src/aptl/backends/aces.py` for the `RuntimeTarget` wiring and
  `AptlProvisioner`.
- `src/aptl/backends/aces_realization.py` and
  `src/aptl/backends/aces_realization_model.py` for the interpret stage and its
  typed output.
- `src/aptl/backends/aces_profiles.py` for curated compatibility only. It is
  not the paper-scenario topology driver.
- `src/aptl/backends/aces_diagnostics.py` for the supported-resource-type set
  and diagnostics.
- `src/aptl/backends/aces_manifest.py` for the realization support declaration.
- `src/aptl/core/deployment/` for every Docker, Compose, container, and host
  operation, including image pull/build/tag, network/IPAM side effects, and
  content copy/write side effects.
- `src/aptl/core/runstore.py`, `src/aptl/core/snapshot.py`,
  `src/aptl/core/config.py`, and `src/aptl/core/env.py` for run persistence,
  inventory evidence, config, and env binding.

Tests extend the existing ACES backend and realization seams
(`tests/test_aces_backend.py` and the realization-focused tests) rather than
introducing a new harness.

## Extensibility

The extensibility seam is the boundary between the interpreted realization and
the driver. Interpret produces a typed `AptlRealization` from the compiled plan;
the compatibility driver maps that realization onto compose profiles. For the
paper scenario and later fully dynamic scenarios, the driver consumes the typed
realization spec directly through `DeploymentBackend`. A new authored resource
type is added by extending `SUPPORTED_RESOURCE_TYPES` and the interpreter, then
adding a typed backend realization operation when runtime side effects are
needed, without adding a second topology authority or branching on a specific
scenario name.

The design must stay parameterized by scenario identity and backend manifest
version. It must not assume TechVault is the only scenario, that Docker Compose
is the only possible realization vehicle, or that the current realization
support mode is static.

For networks, the parameterized seam is the typed attachment record:
scenario network id, backend network id, optional CIDR/gateway/internal policy,
node id, backend container/service id, optional static address, and provenance
for the authored link. Future scenarios should be able to vary segmentation,
addressing, and egress policy without editing the compatibility
`docker-compose.yml` network block or branching on scenario names.

For image realization, the extensibility seam is the tuple of ACES source
identity, optional build provenance, image trust policy, resolved image
reference/digest, backend provider, and platform/build context. The next likely
change is multi-architecture images, registry authentication, SBOM/attestation
checks, or another backend provider. Those should add policy fields or typed
backend parameters, not scenario branches or Compose-service rewrites.

For content placement, the extensibility seam is the typed content-placement
record: ACES content address/name, content type, target node/container, target
path or destination, source reference or inline/item-derived materialization
input, sensitivity class, digest/checksum, permissions/owner when ACES grows
that contract, and realization provenance. Future changes such as binary
source packages, per-file mode/owner, generated datasets, DB-specific importers,
or another backend provider should add fields to that typed seam, not a
scenario branch, duplicate content schema, or raw backend command string.

## Consequences

### Positive

- The compiled scenario, not a hand-edited compose file, decides range
  topology. A new scenario realizes without editing `docker-compose.yml`.
- SEM-218 open and closed semantics are honored through the ACES planner gate,
  so APTL's realization claims are contract-validated rather than asserted.
- Realization evidence rides the existing run record (ADR-044); there is no new
  record type to maintain or redact.

### Negative / costs

- The profile index must track the compose file. A profile that exists in
  `docker-compose.yml` but is unmapped, or mapped but absent, is a realization
  gap the index and its tests must catch.
- APTL's realization support declaration must stay honest. Widening the claimed
  realization support without the interpreter and driver to back it would let
  the planner gate pass scenarios APTL cannot actually realize.

### Risks

- An authored scenario can carry resource types APTL does not interpret. The
  diagnostic-not-failure choice keeps the apply running, so the operator must
  read realization diagnostics rather than assume a clean apply realized every
  authored concern.

## Non-Goals

- This ADR does not replace `docker-compose.yml` as the realization vehicle. It
  removes the file's role as topology authority, not the file.
- This ADR does not define a new run-record type, scenario schema, or ACES
  mirror model. Realization evidence rides ADR-044's record.
- This ADR does not change APTL's backend profile claim. The manifest and
  conformance gates remain the source of truth for that claim.

## Anti-Patterns

- Treating a scenario name as a profile selector instead of deriving profiles
  from the interpreted realization.
- Using `select_backend_profiles` or `ComposeProfileIndex` as the topology
  driver for the paper scenario.
- Extending `DEFAULT_PARTICIPANT_ACTIONS` with paper-scenario behavior instead
  of deriving participant action specs from compiled SDL/runtime artifacts.
- Emitting participant snapshot entries or shared-state scopes with legacy
  TechVault SSH identifiers after the runtime selected a different participant
  action binding.
- Calling `docker` or `docker compose`, or parsing compose output, from the
  interpret or driver stage instead of routing through `DeploymentBackend`.
- Resolving node images by reading whatever image/build block a pre-existing
  Compose service pins, or treating a Compose profile match as image identity.
- Treating ACES `Source.name` / `version` as a raw Docker image reference until
  it has passed the APTL image resolver and trust policy.
- Building from raw Docker history strings, unbounded Dockerfile text, or
  unvalidated build context paths instead of typed `source.build` provenance and
  project-contained backend operations.
- Echoing disallowed image refs, registry credentials, build arg values,
  rendered Dockerfile text, or backend stderr in diagnostics, logs, snapshots,
  API responses, or run records.
- Treating content placements as interpreted records only, descriptor-only
  metadata, run evidence, volume seeds, or participant observations instead of
  target-container state.
- Reusing named-volume seed shell snippets for scenario-authored content without
  a stricter authored-path/content boundary.
- Materializing control-plane/operator secrets from `.env`, generated config,
  host private keys, registry credentials, or operator state as authored
  content.
- Storing raw content bytes, dataset rows, source packages, backend stderr, or
  secret-bearing rendered content in realization evidence.
- Re-evaluating SEM-218 explicitness classes with a local model rather than
  consuming `realization_requirements` and the planner gate.
- Adding a second topology authority, a duplicate compose parser, or a local
  `RuntimeModel` mirror.
- Writing realization evidence to a new record type instead of `LocalRunStore`
  and `RangeSnapshot`, or storing secret values rather than digests and
  non-secret identities.

## References

- [ADR-025](adr-025-strict-first-party-config-schema.md): strict first-party
  config schema for non-secret realization knobs.
- [ADR-029](adr-029-control-plane-secret-handling.md): runstore and snapshot
  redaction boundaries.
- [ADR-035](adr-035-aces-sdl-adoption.md): ACES SDL adoption; this ADR
  supersedes its Parity Inventory Boundary realization model while preserving
  its SDL adoption and backend-manifest/conformance model.
- [ADR-037](adr-037-docker-compose-backend-cohesion.md): all Docker and Compose
  operations route through `DeploymentBackend`; the runner boundary is the
  extensibility seam.
- [ADR-044](adr-044-aces-aligned-run-reproducibility-record.md): realization
  evidence rides the run reproducibility record rather than a new type.
- SEM-218 (ACES compiled realization requirements) and RUN-314 / autarchy-ai/aces#197
  (reference emulation backend).
- Related issues: [#554](https://github.com/Brad-Edwards/aptl/issues/554),
  [#556](https://github.com/Brad-Edwards/aptl/issues/556) (superseded paper
  scenario path), [#573](https://github.com/Brad-Edwards/aptl/issues/573),
  [#576](https://github.com/Brad-Edwards/aptl/issues/576),
  [aces#598](https://github.com/Brad-Edwards/aces/issues/598), and
  [aces#600](https://github.com/Brad-Edwards/aces/issues/600); DSL-008 /
  [#422](https://github.com/Brad-Edwards/aptl/issues/422).
