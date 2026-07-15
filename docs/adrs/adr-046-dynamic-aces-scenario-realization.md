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

## Paper Scenario Evidence Modeling Addendum

Issue #691 removes an accidental equivalence between content placement and
evidence. In ACES SDL, `content` means material intended for placement on a
scenario target. It is not a generic carrier for an observation, an authored
capture obligation, or a captured evidence record. The paper scenario therefore
must not represent participant output, Wazuh evaluator evidence, or negative
boundary-check evidence as `type: dataset` content merely to give those concepts
names.

The existing ACES carriers remain authoritative:

- `observation_boundaries` owns the participant projection and identifies the
  runtime-emitted participant observation. The portable runtime carrier is the
  existing `participant-observation-envelope-v1`; a second APTL observation DTO
  or dataset schema is not permitted.
- `evidence_requirements` owns portable capture intent for Wazuh corroboration
  and negative boundary checks. Each requirement declares its source or source
  class, scope, window/trigger/boundary, channel, sensitivity, redaction,
  integrity, retention, and loss-disclosure expectations through the ACES
  schema. A requirement is not proof that capture occurred.
- Actual evidence and capture success remain runtime concerns. Conditions and
  objective assertions may report observed success; `RuntimeSnapshot`,
  `AptlEvaluator`, and `LocalRunStore` carry or reference captured records.
  `evidence_requirements.*` entries are deliberately not objective targets.

Backend-only participant binding data is also not participant content. When the
paper binding moves off `content`, it must reuse the compiled
`behavior_specifications` governed-extension seam (`x-aptl:*`) and the existing
`aptl-participant-runtime-binding/v1` validation/parser contract. Do not create a
new top-level SDL section, a second binding schema, or a paper-scenario lookup in
Python. A task brief remains genuine participant-visible content only if it
lowers through the existing typed content realization path to a registered,
project-scoped backing volume. Adjudication prose that is not actually placed is
not content and must not be relabeled as an evidence requirement.

The participant projection is a security boundary, not descriptive prose. Raw
Wazuh data, database or Wazuh endpoint identities, backend commands, evaluator
notes, and negative-check internals must not appear in participant-visible
output or in snapshot fields marked observable/disclosed. Evaluator evidence may
be referenced from the observation boundary as `evidence_only`; its payload
remains behind the existing run-record redaction and persistence boundaries.

The static gate must prove the whole content surface, not only the three removed
datasets: every remaining paper-scenario `content-placement` lowers to a typed
`DeploymentContentRealization`, and interpretation emits no
`aptl.provisioner.content-placement-rejected` diagnostic. The gate also asserts
the authored evidence requirements and observation-boundary projection through
the parsed ACES models. It must not special-case the scenario in the content
resolver, widen manifest dataset support, or treat the absence of a planner
diagnostic as proof of backend realization.

The extensibility seams are the map-keyed ACES evidence requirement (parameterized
by source, scope, boundary/window, channel, and handling expectations), the
compiled observation-boundary address, and the governed behavior-specification
extension keyed by backend owner. The next scenario can vary those values
without changing the ACES schema, the content realizer, or a scenario-name
branch.

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

## Runtime Service and SEM-218 Execution Addendum

Issue #578 completes runtime-service realization and the SEM-218 execution
wiring. The public ACES execution owner is `RuntimeManager.apply()`: its backend
call boundary validates `ApplyResult`, runs `realization_disclosure` with
`ExecutionPlan.model.realization_requirements`, rejects silent approximation,
and attaches `RealizationProvenanceEntry` values to the returned
`RuntimeSnapshot`. APTL must use that path rather than call
`realization_disclosure` itself, mutate control-plane snapshot internals, or
reimplement phase ordering and provenance attachment.

The provisioner's returned `RuntimeSnapshot` must describe backend-observed
realization. `snapshot_after_apply()` is only the snapshot assembler; neither a
planned resource payload, a successful lowering, nor a successful materializer
call is evidence of runtime state. A resource may enter the successful snapshot
only after the deployment backend has started and inspected the concrete
project-scoped resource and verified every concern the snapshot claims. Backend
inspection continues through typed `DeploymentBackend` operations; the ACES
adapter must not call Docker or parse Compose output directly.

Issue #692 makes that rule explicit for every SEM-218 concern in
`aces_processor.semantics.realization.CONCERN_PAYLOAD_PATH`. The existing
`aptl.backends.aces_observation.observe_realization()` boundary owns the
translation from backend evidence to concern values; APTL must not copy the
registry, derive a second concern schema, or read a concern back from the plan:

- `node-type` is disclosed only after a concrete, project-owned backend object
  of the corresponding kind is observed: a project-labelled container for
  `vm`, or a project-scoped network for `switch`. Resource routing or a planned
  `node_type` value is not evidence.
- `os-family` comes from the inspected project-owned container platform and is
  normalized into the ACES vocabulary. A missing, malformed, or unsupported
  platform is omitted; it is never guessed from an image name, Compose service,
  host OS, or planned `os_family`.
- `content-type` requires read-back of the realized destination's actual
  filesystem kind after materialization. A successful seed, a running target
  container, `DeploymentContentRealization.source_kind`, and the planned
  `spec.type` are expectations or prerequisites, not observed type. Read-back
  consumes the existing typed `DeploymentContentRealization` and resolves the
  project-scoped target/volume through `DeploymentBackend`; it returns only the
  ACES kind, never content bytes or command output.

An absent object, wrong project label, ambiguous binding, malformed inspection
shape, non-zero probe result, timeout, or backend I/O error produces no observed
concern. It does not fall back to the plan. For an `EXACT` requirement that
omission or mismatch is rejected by ACES as
`runtime.backend-contract-invalid`; non-exact concerns remain undisclosed
rather than being fabricated. Snapshot assembly may preserve non-concern fields
only where the ACES reconciliation contract requires them. In particular, probe
stdout/stderr and sensitive inline content must not enter `RuntimeSnapshot`,
`ApplyResult.details`, logs, API errors, telemetry, or run records.

Service concepts must remain distinct while they pass through the existing
`AptlRealization` to `DeploymentRealizationSpec` seam:

- ACES `Node.services` declares container-facing service bindings (name,
  container port, and transport protocol). It is not a Compose service name, a
  process-start command, or a host publish.
- `runtime.health.status` is a required observed state. It is not a healthcheck
  command. A mapped image or Compose service must provide the actual healthcheck;
  if `healthy` is required and the backend reports no healthcheck, realization
  fails rather than treating `running` as equivalent.
- `runtime.network.published_ports` owns host exposure and preserves host IP,
  host port, container port, and transport protocol as separate fields. Do not
  infer host publishing from `Node.services` or hardcode published ports in the
  endpoint registry. Runtime evidence comes back through backend inventory and
  the existing `ContainerSnapshot.ports` normalization.

Starting, waiting for, and inspecting declared services belongs inside the
typed deployment realization operation so a successful `LabResult` means the
declared service topology is running and its required healthchecks have passed.
The later lab-orchestration readiness and live-validation gates remain
independent operational evidence; they must not be the first place a failed
realization is discovered. Reuse the backend runner, project name and labels,
timeouts, SSH transport, argv-list construction, host-port probing, and
`LabResult` / `BackendTimeoutError` envelope. Do not return raw backend stderr
through diagnostics, logs, API responses, or run records.

Host publishing is also a security decision. Existing SOC and control-plane
services inherit the loopback-only policy pinned by ADR-034 and
`tests/test_docker_compose_port_bindings.py`; deliberate target surfaces remain
separately classified. An omitted host address must not silently become
all-interface exposure. A new dynamic publish that cannot be classified by the
existing exposure policy fails closed until that policy is extended. Host-port
conflicts reuse `src/aptl/core/host_ports.py`; an exact authored binding must be
rejected when unavailable rather than silently remapped.

Realization provenance uses the ACES `RealizationProvenanceEntry` contract and
its `author-declared`, `processor-derived`, and `backend-realized` vocabulary.
APTL must not define a parallel provenance enum or infer processor provenance
from field values. If the selected ACES dependency does not carry classifier
provenance through `CompiledRealizationRequirement` into the runtime disclosure
gate, that dependency contract must be updated before APTL can claim
processor-derived provenance support.

The extensibility parameter is the per-node typed service binding: ACES resource
address, backend service/container identity, container endpoint, optional host
publish, required health state, and non-secret provenance reference. The next
scenario can vary ports, protocols, host exposure, and health expectations by
changing compiled input, without editing a scenario-name branch, the endpoint
registry, or a second Compose parser.

## Account and Identity Realization Addendum

Issue #577 replaces the account-placement compatibility proof introduced for
the TechVault operational scenario with real backend-owned account
materialization. Parsing an account placement, carrying it in
`DeploymentRealizationSpec.accounts`, or finding the same username in
`containers/ad/provision-users.sh` is not realization. The declared groups and
account attributes must be applied to the resolved target through
`DeploymentBackend`, and backend success must include a read-after-write check
of the non-secret declared state.

The authoritative input remains the ACES `account-placement` resource and the
compiled SEM-218 account-feature requirements. APTL must consume the released
ACES account-feature extraction, capability-envelope, explicitness, and
realization-provenance contracts. It must not add a local account schema, a
local feature classifier, or a second explicitness model. In particular,
`aces_backend_protocols.account_features.provisioner_account_features` is the
canonical mapping from an account spec to governed feature terms. APTL's
manifest may advertise only the terms its backend materializes and verifies;
an unsupported term is a blocking ACES diagnostic, not a silently ignored
field. `password_strength` is non-secret policy metadata, not a credential. It
may be claimed as realized only when the consumed ACES contract governs it and
the target provider can enforce it without disclosing the resulting secret.

`DeploymentAccountRealization` remains the single APTL backend-facing account
record. It carries the placement address, target-node address, governed
non-secret attributes, and enough provider binding to resolve the concrete
backend-managed node. The corresponding `DeploymentNodeRealization` remains
the authority for service/container identity; account code must not accept an
independent caller-supplied container name. Group names on account placements
are materialized before membership is reconciled and are deduplicated per
target. They do not justify an APTL-local `Group`, directory, repository, or
identity schema: ACES currently models them as account feature values.

Provider selection is a small, code-owned binding from the resolved backend
service/provider kind to its account materializer. The first supported binding
is the Samba AD service on the realized `ad` node. It is not a TechVault or
scenario-name branch. An account targeting an ambiguous node or a service with
no registered account materializer fails validation before account side
effects. A future POSIX, Windows-local, or directory-service provider adds one
binding and provider implementation while consuming the same typed placement;
it does not widen `container_exec` into a generic provisioning API.

Account realization is a post-start operation because the target identity
service must be running. The Compose backend starts the selected services,
completes topology reconciliation, waits for the target provider's bounded
readiness condition, then applies the account batch before returning a
successful `LabResult`. The full batch is provider-validated before the first
account mutation. Application is deterministic and convergent: ensure declared
groups, create or update the user, reconcile every supported explicitly
declared attribute, and verify the resulting non-secret state. A retry after a
timeout or partial failure must converge without duplicate users/groups.
Existing undeclared accounts and memberships are not deleted by this issue;
future delete support must carry ACES `ChangeAction` through the typed boundary
rather than infer desired deletion from absence.

Provider validation is defense in depth, not a duplicate SDL validator. ACES
owns shape, reference, controlled-vocabulary, capability, and SEM-218 checks.
Before mutation, the account materializer additionally rejects provider-invalid
or ambiguous identities, duplicate declarations with conflicting attributes,
control characters/NULs, unsafe lengths or provider syntax, and an attribute
the selected provider cannot faithfully apply. Values travel as structured
arguments or provider API data, never interpolated shell. Identity values such
as usernames, group names, mail addresses, and SPNs are not control-plane
secrets, but untrusted values still must not become shell syntax, option names,
paths, or unbounded log fields.

No plaintext credential crosses the ACES/APTL realization or evidence
boundary. `DeploymentAccountRealization`, `AptlRealization.details()`,
`ApplyResult.details`, diagnostics, snapshots, run records, logs, and telemetry
contain only non-secret identity/policy fields and provenance. Credentials are
generated or resolved inside the target/provider boundary and are never put in
Docker/Compose/process argv, environment variables, exception text, raw stderr
hints, generated Compose overrides, or persisted request/response files. A
provider API or descriptor/stdin mechanism must be used when a credential is
needed; invoking a CLI that requires a password as a positional argument is not
permitted. A failure returns a bounded `LabResult` message naming the placement
address and stable reason, reusing `BackendTimeoutError` for timeouts and the
existing ACES diagnostic/error-envelope translation. Do not add an account-only
exception hierarchy or expose backend stdout/stderr.

Runtime evidence reuses `snapshot_after_apply`, ACES
`RealizationProvenanceEntry`, `RangeSnapshot.to_dict()`, and `LocalRunStore`.
Account-feature provenance names the placement, field path, requirement kind,
explicitness, and author-declared/backend-realized classification; it never
contains the credential or a derived verifier/hash. Defaults and omitted fields
must not be reconstructed locally from empty strings or false values: consume
the upstream explicitness/provenance contract so only the fields the author made
authoritative are claimed as such.

The static `check_account_provisioner_parity` regex scan is superseded as an
account-realization authority. The service-owned script may remain a source of
additional baseline lab fixtures, and the backend must reconcile cleanly when a
declared account already exists, but script text is neither a schema nor runtime
proof. Static validation proves ACES parse/compile/plan, capability-envelope,
SEM-218 lowering, target/provider binding, and typed backend input. The clean
live gate proves users, groups, memberships, and declared attributes by querying
the target through `DeploymentBackend` after `aptl lab stop -v && aptl lab
start`.

## TechVault Operational Standup Addendum

Issue #689 makes `scenarios/techvault-operational.sdl.yaml` the honest dynamic
TechVault startup contract. The operational SDL is the public `aptl lab start`
target listed in `scenarios/catalog.json`; it does not depend on a deep
captured TechVault inventory (see the Capture Inventory and Parity-Inventory
Removal Addendum below—that review-evidence surface has since been removed
from APTL). The operational SDL must not import or depend on captured
`runtime-observed:` content,
`datasets-in-services`, inventory-only filesystem manifests, logs, database
dumps, screenshots, or runtime state that APTL cannot recreate from source on a
clean machine.

The acceptance bar is compose-guaranteed fidelity from authored ACES resources
through APTL's interpret-then-driver path. Nodes, images, networks,
attachments, content placements, and account placements must compile through
ACES, enter `interpret_provisioning_plan`, appear in typed realization details,
and be either realized by `DeploymentRealizationSpec` / `DeploymentBackend` or
explicitly rejected by an ACES diagnostic before side effects. A placement that
is merely counted in `AptlRealization.details()` is not dynamic realization.

Content in the honest operational SDL is limited to realizable content:

- file content provided as bounded inline text;
- file content sourced from a project-contained, checked-in path;
- directories whose materialized contents are sourced from project-contained,
  checked-in paths or explicit empty-directory declarations.

Do not encode runtime-observed files, generated service config, mutable volume
state, database rows, index contents, captured package manifests, or arbitrary
container filesystem trees as operational content. If #576's content
realization seam is present, `AptlRealization` should lower those ACES
placements into its canonical typed backend input and the Compose backend
should reuse existing containment and named-volume/container-copy precedents,
including `NamedVolumeSeed`, project-scoped volumes, argv-list commands,
redacted `LabResult` failures, and `BackendSeedError` / `BackendTimeoutError`
behavior where applicable. If that seam is absent, #689 is blocked or must add
a narrow typed placement operation to `DeploymentBackend`; it must not add raw
Docker calls, a second content schema, or a scenario-name special case.

Account declarations must be equally honest. Lab fixture accounts may be
declared only when the clean startup path actually creates or preserves them
through an existing service-owned provisioning path or a new typed backend
account-placement operation. They must not rely on post-capture drift. Designed
weak target credentials are scenario fixture data; operator/control-plane
secrets remain under `EnvVars`, `.env`, rendered config, and ADR-029 redaction.
Do not serialize Wazuh, MISP, TheHive, Shuffle, registry, SSH private key,
cookie, token, hash, or generated enrollment material into the SDL, run
evidence, diagnostics, or snapshots.

The manifest honesty rule is strict: APTL may claim `file`, `directory`,
`dataset`, account, image, or network support only to the extent that the ACES
planner gate, interpreter, typed backend spec, deployment backend, static tests,
and live clean-start gate prove that support for the authored TechVault
surface. A broad `ProvisionerCapabilities` value is not a waiver for a
no-op interpreter branch.

## Capture Inventory and Parity-Inventory Removal Addendum

Issue #690 removes the captured TechVault asset inventory
(`docs/aces/inventory/`) and the SCN-010 parity-inventory surface
(`docs/aces/parity-inventory.yaml` / `.md`, `check_parity_manifest`, and the
`required_surface_coverage` contract in the static validation gate) from
APTL. That capture was an experiment run inside APTL to prove out an
asset-inventory capability; the capability itself now lives in ACES
(`docs/aces/inventory/asset-inventory-methodology.md` at
Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md).
APTL is an ACES-conformant backend: it keeps only the operational SDL
(`scenarios/techvault-operational.sdl.yaml`) as the driving contract, with no
separate capture/parity evidence surface behind it.

The removed capture output is recoverable from git history if ever needed: the
capture SDL (`scenarios/techvault.sdl.yaml`) and its supporting tree
(`scenarios/techvault/`, `scenarios/aces.lock.json`) were deleted in PR #745
(`205e47d^` is the last commit carrying them); the per-asset inventory
bundles under `docs/aces/inventory/` were deleted in the PR that closes #690
(its parent commit carries them).

## Security Layers

| Layer | Requirement |
| --- | --- |
| ACES parser and compiler gate | Authored scenarios enter through `aces_sdl.parse_sdl_file` and compile through the ACES compiler and planner. APTL does not structurally revalidate ACES SDL or recompile the `RuntimeModel` with local models. |
| Realization requirement gate | SEM-218 open and closed semantics are enforced by the ACES planner's `realization_support_diagnostics` against APTL's `RealizationSupportDeclaration`. APTL reads `realization_requirements`; it does not re-derive explicitness classes locally. |
| Runtime observation gate | `observe_realization()` emits concern values only from project-scoped backend read-back, using ACES's `CONCERN_PAYLOAD_PATH`. Missing, malformed, timed-out, or mismatched evidence omits the concern and lets `RuntimeManager.apply()` fail an exact requirement closed; it never falls back to planned payload values. |
| Deployment boundary gate | The curated compatibility path may still drive `DeploymentBackend.start_lab` with profiles. The paper scenario drives typed `DeploymentBackend` realization methods. No ACES adapter code calls raw Docker, `docker compose`, or parses compose output directly (ADR-037). |
| Image trust gate | Node image pull/build decisions are made from ACES `Source` / `source.build` payloads and pass an APTL image policy before backend side effects. Untrusted or insufficient image inputs fail closed through ACES diagnostics without echoing raw image refs, build args, credentials, Dockerfile text, or backend stderr. |
| Network topology gate | Network creation, IPAM, `internal` egress policy, and per-node attachments come from typed realization specs. Backend validation parses CIDR/gateway/static IP values, preserves project scoping, labels backend-created networks, and fails closed before side effects when authored exact/constrained values cannot be honored. |
| Content placement gate | Operational TechVault content must be bounded inline text, project-contained checked-in file source, or project-contained checked-in directory source lowered into typed backend placement input. Path containment, safe relative-path validation, project-scoped volumes/copies, and redacted backend failures reuse existing deployment and seed precedents; captured runtime content is rejected. |
| Account placement gate | ACES parser/compiler, canonical account-feature extraction, manifest capability checks, and SEM-218 explicitness/provenance run before the backend. The backend resolves the placement only through its typed target node, validates the full batch and provider syntax before mutation, then creates/reconciles groups and accounts after bounded provider readiness and verifies non-secret state. Raw credentials, hashes, provider stderr, and caller-supplied container identities remain outside typed inputs and evidence. |
| Config and env binding | Non-secret realization knobs bind through strict `AptlConfig`; runtime secrets stay in `EnvVars` and `.env`. The realization record stores digests and non-secret identities, never `.env` values, rendered config, tokens, or key material. |
| Persistence and redaction | Realization details, selected profiles for compatibility scenarios, typed realization specs for dynamic scenarios, and evaluator-only evidence enter JSON through `LocalRunStore` and `RangeSnapshot.to_dict()`, inheriting ADR-029 redaction and path-containment checks. |
| Static and live validation gate | Static tests prove the SDL parses, plans, and lowers to a realizable typed spec without unsupported or no-op placements. The live gate remains a clean `aptl lab stop -v && aptl lab start` with health/readiness checks, not a comparison to captured inventory state. |

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
- `src/aptl/backends/aces_observation.py` for backend evidence-to-concern
  translation, using the ACES-owned concern path registry rather than an
  APTL-local schema.
- `src/aptl/backends/aces_manifest.py` for the realization support declaration.
- `aces_backend_protocols.account_features.provisioner_account_features` for
  the governed account-spec-to-feature mapping; do not copy that decision table
  into APTL.
- `src/aptl/core/deployment/` for every Docker, Compose, container, and host
  operation, including any future image pull/build/tag and network/IPAM side
  effects.
- `src/aptl/core/seed_spec.py` and existing named-volume seed behavior for
  project-contained source-to-runtime materialization when content placement
  needs file or directory side effects.
- `src/aptl/core/runstore.py`, `src/aptl/core/snapshot.py`,
  `src/aptl/core/config.py`, and `src/aptl/core/env.py` for run persistence,
  inventory evidence, config, and env binding.
- `scenarios/techvault-operational.sdl.yaml` and `scenarios/catalog.json` for
  the public TechVault ACES startup selection.

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

For content and account realization, the seam is a typed placement record:
ACES placement address, target node/service/container, content or account
identity, non-secret provenance, bounded source kind, destination kind, and the
backend materialization operation. Account provider kind is resolved from the
typed target binding, not from scenario identity. Future scenarios should be
able to vary which checked-in source directory, inline file, target node,
account fixture, or provider backend is used without editing TechVault-only
code. Future account deletion/replacement reuses ACES `ChangeAction`; it must
not add an APTL-only lifecycle enum.

For runtime disclosure, the parameterized seam remains
`observe_realization(DeploymentBackend, AptlRealization, ProvisioningPlan)` and
the existing typed realization records. A new backend or a new ACES concern
adds provider-owned read-back behind `DeploymentBackend` and maps only the
observed value at this boundary. The ACES concern kind/path registry, runtime
gate, snapshot DTO, and provenance vocabulary remain upstream-owned and are not
extended with APTL mirrors.

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
- The honest TechVault SDL may be smaller than the captured inventory. Omitting
  non-realizable captured facts is correct; carrying them as no-op operational
  placements is not.

### Risks

- An authored scenario can carry resource types APTL does not interpret. The
  diagnostic-not-failure choice keeps the apply running, so the operator must
  read realization diagnostics rather than assume a clean apply realized every
  authored concern.
- Manifest capability text can drift ahead of backend behavior. The static
  lowering tests and clean-start live gate must catch claims that are parsed
  and counted but never passed to a typed backend operation.
- `RuntimeSnapshot.payload` participates in ACES reconciliation as well as
  disclosure. Removing non-concern fields blindly can force perpetual updates,
  while copying a sensitive planned payload can leak it into the run record.
  Preserve only contract-required reconciliation state and keep sensitive
  content and probe output outside the snapshot; a broader split between
  desired-state fingerprints and observed evidence belongs in ACES, not an
  APTL-only snapshot schema.
- Disclosure failure happens after backend side effects. It rejects the apply
  and restores the baseline control-plane snapshot, but it is not transactional
  rollback of already-created containers, networks, or volumes. Do not report
  failed observations in `changed_addresses`; cleanup remains the established
  lab stop/kill workflow unless ACES adds an apply rollback contract.

## Non-Goals

- This ADR does not replace `docker-compose.yml` as the realization vehicle. It
  removes the file's role as topology authority, not the file.
- This ADR does not define a new run-record type, scenario schema, or ACES
  mirror model. Realization evidence rides ADR-044's record.
- This ADR does not change APTL's backend profile claim. The manifest and
  conformance gates remain the source of truth for that claim.
- This ADR does not require the operational TechVault SDL to reproduce every
  captured inventory fact. It requires every authored operational fact to be
  dynamically realizable or rejected before startup side effects.
- Issue #577 does not add operator identities, control-plane authentication,
  RBAC, secrets management, or a general directory-service API. It does not
  delete accounts/groups absent from the scenario or migrate the additional
  baseline fixtures in `provision-users.sh`.
- Issue #692 does not add a second disclosure gate, a new runtime snapshot or
  evidence schema, an API surface, operator-configurable probe commands, content
  equality/integrity attestation, or transactional provisioning rollback.

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
- Adding `runtime-observed:` content, `datasets-in-services`, database dumps,
  log excerpts, package manifests, or arbitrary captured filesystem trees to
  the operational TechVault SDL.
- Treating `content-placement` or `account-placement` resource counts as proof
  of realization when no typed backend operation consumes the placement.
- Treating a successful seed, a running/healthy target container, the typed
  placement's source kind, or `spec.type` as read-back proof of the realized
  content type.
- Treating a matching line in `provision-users.sh`, a successful create command,
  or an existing username as proof that groups and declared attributes were
  realized; backend success requires non-secret read-after-write verification.
- Keeping `check_account_provisioner_parity` as a second account authority after
  backend realization lands, or parsing shell scripts/Compose text to derive
  account state.
- Re-implementing ACES account-feature extraction, explicitness, capability, or
  provenance rules in APTL, or advertising a manifest feature the selected
  account provider does not apply and verify.
- Passing a plaintext credential through a realization DTO, Docker/Compose or
  process argv, environment, generated file, log, exception, stderr hint,
  snapshot, telemetry attribute, or run artifact.
- Building a generic remote-command/account-service abstraction, accepting a
  caller-supplied container id, or branching on the TechVault scenario instead
  of resolving a registered provider from the typed target node.
- Hiding an unrealizable content/account fact in `metadata`, comments,
  `x-aptl-*`, inventory ledger rows, or a TechVault scenario-name branch.
- Duplicating the content schema, account schema, path-containment checks,
  volume seed behavior, credential taxonomy, or redaction policy instead of
  reusing the existing ACES/APTL owners.
- Echoing disallowed image refs, registry credentials, build arg values,
  rendered Dockerfile text, or backend stderr in diagnostics, logs, snapshots,
  API responses, or run records.
- Re-evaluating SEM-218 explicitness classes with a local model rather than
  consuming `realization_requirements` and the planner gate.
- Copying gated concern values from a `ProvisioningPlan`, or falling back to
  them when inspection is unavailable; accepting a same-named container without
  the configured Compose project label; or logging raw probe output.
- Adding a second topology authority, a duplicate compose parser, or a local
  `RuntimeModel` mirror.
- Writing realization evidence to a new record type instead of `LocalRunStore`
  and `RangeSnapshot`, or storing secret values rather than digests and
  non-secret identities.
- Reintroducing captured runtime-observed content (a per-asset inventory
  tree, evidence bundles, or a `capture-evidence.sh`-style runner) into APTL;
  that capture capability lives in ACES, not here.
- Reintroducing a parity-inventory surface (a `required_surface_coverage`
  manifest, a `check_parity_manifest`-style gate check, or a
  represented/deferred contract) as a condition of the static or live
  validation gate.

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
  [#574](https://github.com/Brad-Edwards/aptl/issues/574),
  [#575](https://github.com/Brad-Edwards/aptl/issues/575),
  [#576](https://github.com/Brad-Edwards/aptl/issues/576),
  [#689](https://github.com/Brad-Edwards/aptl/issues/689),
  [#692](https://github.com/Brad-Edwards/aptl/issues/692),
  [aces#598](https://github.com/Brad-Edwards/aces/issues/598), and
  [aces#600](https://github.com/Brad-Edwards/aces/issues/600); DSL-008 /
  [#422](https://github.com/Brad-Edwards/aptl/issues/422).
