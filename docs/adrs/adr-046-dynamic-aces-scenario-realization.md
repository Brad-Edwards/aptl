# ADR-046: Dynamic ACES Scenario Realization

## Status

accepted (amended 2026-07-20)

## Date

2026-06-29

## Last Updated

2026-07-20

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

> **Superseded by [ADR-047](adr-047-image-free-placement-realization.md)
> (2026-07-20).** APTL no longer realizes a node's scenario-meaningful
> software, services, content, accounts, or configuration from a pulled or
> built *appliance* image. A node's realized state comes from the ACES
> `ProvisioningPlan`'s placements (`feature-binding`, `content-placement`,
> `account-placement`) applied onto a generic base substrate, at
> docker-compose granularity or better. A generic OS base image is still a
> permitted container substrate; an appliance image that encodes the range
> outside the SDL is not. The pull/build model described below is retained only
> for historical context and for a generic base substrate; it is not the
> node-realization authority. See ADR-047 for the current model.

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

## Heavy Stateful Service Realization Addendum

Issue #579 applies the interpret-then-driver boundary to Wazuh manager and
indexer, including their generated certificate material, rendered manager
configuration, and mutable persistent volumes. These concerns form one
addressed dependency graph but remain distinct resource concepts. Generated
configuration is not content placement, a certificate/key bundle is not an
ordinary copied file, and an empty mutable named volume is not a content seed.
ACES 0.21 left an important boundary ambiguous:
`RuntimeConfiguration` describes `Node.runtime` as declarative required state,
while `RuntimeMount` and its stability/sensitivity vocabulary describe observed
runtime facts. APTL must not resolve that ambiguity by interpreting the nested
node payload as an APTL-local desired-volume schema. The upstream contract must
clarify and compile the intended semantics while reusing the existing mount
vocabulary where it fits.

The released ACES contract remains authoritative. APTL may consume an upstream
extension of the existing configuration/artifact feature and dependency model,
but it must not make `metadata`, `x-aptl-*`, scenario-name branches, or a local
Pydantic mirror authoritative for generated artifacts, consumers, mount
destinations, sensitivity, lifecycle, or provenance. If the selected ACES
release cannot compile those facts into addressed realization resources and
SEM-218 requirements, the gap is blocking: file and fix it upstream, consume a
released version in `pyproject.toml`, and lock its artifact and hash in
`uv.lock` before advertising or accepting the capability. A sibling checkout
or an unpinned VCS dependency is not contract evidence.

That gap was resolved upstream by ACES #780/#782 and hardened by ACES #816.
APTL consumes the published `aces-sdl` 0.23.1 release, which provides typed,
addressed generated-artifact and persistent-volume resources; declared outputs
and consumers; lifecycle, access, sensitivity, provenance, and dependency
semantics; SEM-218 realization requirements; backend capability disclosure;
and pre-dispatch read-only/RWO admission. `pyproject.toml` requires
`aces-sdl>=0.23.1,<0.24.0`, and `uv.lock` records the published distribution and
hashes. The earlier 0.21 limitation remains historical rationale, not an active
APTL-local schema seam.

`AptlRealization` and `DeploymentRealizationSpec` remain the single translation
and driver DTO boundaries. They carry typed generated-artifact and
persistent-volume records derived from compiled ACES resources; they must not
gain an arbitrary command, shell fragment, generic hook, or provider-specific
Compose blob. All shape, reference, dependency, controlled-vocabulary,
capability, and SEM-218 validation stays in ACES. APTL adds only backend-policy
validation such as provider support, contained output paths, declared output
completeness, mount safety, project-scoped volume identity, and local/SSH
materialization feasibility.

The entire addressed prerequisite and service graph is validated before the
first side effect. The graph must express that certificate/configuration and
volume prerequisites precede their consumers, the indexer reaches its required
state before manager startup, and observation follows startup. The current
operational scenario's reverse indexer-to-manager dependency is not a boot
contract and must not be preserved. Retrying a partially completed graph must
converge: generated artifacts are verified before reuse, named volumes survive
ordinary restart, and project teardown with volume removal owns destructive
cleanup. Future replace/delete behavior carries ACES `ChangeAction`; absence is
not deletion intent. The orchestration must select compatibility ownership or
typed-realization ownership from one validated graph before the existing
generic credential, certificate, and container-start steps mutate anything; it
must not compile again or introduce a second Wazuh lifecycle orchestrator.

The deployment backend owns every side effect and readback. Configuration
realization reuses ADR-028's checked-in immutable template, fixed contained
output under `.aptl/`, placeholder/env binding, symlink rejection, permissions,
and atomic replacement. Certificate realization reuses the existing Wazuh
generator and `config/certs.yml` subject/SAN contract plus the isolated
generator-project cleanup, but invokes it through the ADR-037 backend runner.
Success requires the complete declared output set, key/certificate pairing,
chain and subject/SAN validation, and restrictive host permissions; the mere
presence of `root-ca.pem` or a warning after failed permission repair is not
success. Permissions must be compatible with the non-root container consumer:
the existing private parent-directory plus read-only, container-readable file
pattern is valid when verified, while silent or warning-only permission repair
is not. Wazuh's chain remains separate from ADR-034's lab SOC CA.
The generator may emit a larger administrative bundle, but the realization
mount unit is each artifact's declared output set, not the generator directory.
Indexer, manager, and dashboard therefore receive separate read-only CA and
service-key subsets. Administrative and cross-service private keys remain
unmounted from long-lived consumers.

Persistent Wazuh storage reuses project naming, labels, runner, convergence,
and safe mount conventions from the deployment and named-volume seed paths,
but it is not modeled as `NamedVolumeSeed` or reported through
`BackendSeedError`. Volume identity, consumer, container destination, access
mode, and lifecycle come from the typed graph. Names are stable within the
project, never global or random per start, and the driver verifies the
container's observed mounts after startup. Captured index contents and mutable
manager state are neither SDL content nor reproducibility evidence.

Compose remains a realization vehicle, not an authority for Wazuh identity,
prerequisites, mounts, volumes, dependency order, or evidence. The dynamic path
must not receive acceptance credit by selecting the hand-authored `wazuh`
profile or matching an existing service block. A compatibility service may
remain temporarily for other curated startup paths, but manager/indexer
realization must derive and drive their effective service definitions from the
typed graph. Generated mount sources and overrides must pass the canonical bind
and path checks after generation and before `compose up`; the earlier static
`_step_check_bind_mounts` scan of the base file does not cover later overrides.
The fully merged Compose model must also be inspected before startup. A partial
overlay is insufficient because undeclared base service fields survive Compose
merge and would leave the hand-authored service authoritative. The generated
definition must either stand alone or deliberately reset/override every owned
field. APTL uses service-level `!override` replacement and rejects Docker
Compose versions older than 2.24.4 before artifact mutation, matching the
[Compose merge contract](https://docs.docker.com/reference/compose-file/merge/).
Effective-model inspection must preserve
secret references or redact resolved values in memory; it must never print,
log, or persist a fully interpolated model containing credentials. The generic
lab-start certificate and manager-config steps must not also own artifacts
selected by typed realization. Suppression is keyed by the exact admitted
artifact address, provider, consumer service, and destination; the mere
presence of the same generator kind in an authored scenario cannot suppress an
unrelated compatibility step. The effective model and any ancillary override
use fixed paths under `.aptl/realization/`, reject symlinked path chains, and
are replaced atomically; callers never supply an output path. Stop/restart must
retain the same project and effective-model identity. In particular, `stop -v`
must remove the dynamic volumes through that model or an equivalently
project-scoped, label-validated backend cleanup; running `down -v` against only
the base file must not orphan state that the realization graph created.

Local and SSH backends preserve the same contract. A locally rendered file is
not available to a remote Docker daemon merely because `DOCKER_HOST` is set.
Until the backend has an explicit contained remote-materialization operation,
an artifact-consuming remote realization fails closed before mutation. Secrets,
private keys, rendered config, and resolved credential values never enter ACES
SDL, realization details, generated Compose overrides, process argv, backend
stderr hints, diagnostics, logs, API error envelopes, snapshots, telemetry, or
run records. Compose receives secret references through the existing env
boundary rather than resolved values. Readiness and evidence collection resolve
the existing `EnvVars` credentials at the last responsible boundary and pass
authentication through `curl_safe`'s permissioned header file. A collector's
hard-coded/default credential tuple is test convenience, not an admissible live
gate or evaluator credential source.

A successful snapshot is backend-observed, not a copy of the plan. It records
only non-secret identities and evidence such as addressed step status,
project-scoped volume identity and mount destination/lifecycle, configuration
digest, public-certificate fingerprint and validated SAN/chain status, service
health, and authenticated readiness. Static validation proves ACES
parse/compile/plan/SEM-218 lowering and typed backend inputs without Docker.
`aces_observation.py` must handle each new resource type explicitly; falling
through to content/account placement observation is not valid. A resource is
not ready until provider readback has verified its artifact or mount claims and
the manager/indexer authenticated readiness contract.
The clean live gate remains the canonical runtime proof and must require both
authenticated indexer/manager readiness and an actual Wazuh alert retrieved by
the Wazuh collector. Container health, an evaluator condition that merely sees
a ready node, declared `evidence_requirements`, or a Suricata-only event is not
Wazuh evaluator evidence. The alert must be observed after the bounded trigger
and correlated to that trigger by non-secret event identity; an arbitrary alert
count from stale or unrelated index contents is not evidence. Only a bounded,
redacted summary (for example rule/source identity, event time, correlation or
action identity, and digest) may enter run artifacts. The existing
`AptlEvaluator` result/history contracts must reflect that observation after the
action and evidence probe; the current pre-action, node-readiness-derived
condition result cannot receive acceptance credit, and a parallel Wazuh
evaluator DTO or workflow is not introduced.

The extensibility seam is an ACES-compiled, address-keyed realization resource
graph parameterized by provider kind, target, dependencies, declared non-secret
inputs and secret-reference names, output identities and consumers, sensitivity,
mount target/access, persistence lifecycle, and provenance. Certificate
subjects/SANs/consumers, config renderer/template/output/mount, and volume
identity/destination/lifecycle remain typed parameters rather than Wazuh
branches. A later stateful service can add SDL data and a bounded provider
binding without editing the canonical schema, introducing a generic workflow
engine, or copying Wazuh orchestration.

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

The acceptance bar is backend-guaranteed fidelity from authored ACES resources
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

## TechVault Full Dynamic Cutover Addendum

Issue #581 closes the remaining compatibility gap for
`techvault-operational`. The compiled ACES execution graph and the typed APTL
realization derived from it are the sole deployment authority for the public
TechVault start path. `docker-compose.yml`, `ComposeProfileIndex`, profile
selection, `aptl.json` container switches, package discovery, and tests must no
longer contribute otherwise-undeclared nodes, services, networks, volumes,
mounts, ports, dependencies, commands, health contracts, or lifecycle identity
to that path. Configuration may constrain admission or select a registered
scenario/backend; it is not a second topology language.

Docker Compose remains a backend wire format, not an authored model. The
Compose backend renders one standalone, non-interpolated effective model from
the existing `DeploymentRealizationSpec` at a fixed project-contained path
under `.aptl/realization/`. It must not merge a generated overlay with the
hand-authored base file. A repository-root `docker-compose.yml` is either
removed or emitted deterministically by the same renderer as a derived
reference artifact with a drift check. Public start, stop, kill, retry, status,
clean-volume, packaging, and validation paths must not read that reference as
input.

### Admission and ownership boundary

There is one admitted scenario execution per start attempt. After existing env
and strict config validation, the orchestration path resolves the catalog entry,
parses, compiles, plans, interprets, and validates once, before any
scenario-dependent artifact, volume, image, network, content, or account side
effect. Artifact ownership, host exposure, image preparation, generated model
rendering, startup, observation, retry, and run evidence consume that same
execution-plan identity and typed realization. A helper must not re-plan the
SDL to decide whether it or typed realization owns a side effect.

The existing ACES models and APTL realization DTOs are the only desired-state
schemas. Extend `AptlRealization` and `DeploymentRealizationSpec` where an ACES
compiled field already has runtime meaning; do not introduce an APTL SDL mirror,
a generic Compose-service DTO, or an untyped Compose fragment/command escape
hatch. Node `source`, `services`, and `runtime`, compiled networks and
dependencies, content/accounts, generated artifacts, and persistent volumes
lower through those owners. `Node.services` remains container-facing service
identity; host exposure remains `runtime.network.published_ports`; observed
health remains distinct from the authored readiness/healthcheck mechanism.

The released ACES `RuntimeConfiguration` is already the portable declarative
owner for environment value classification/provenance, mounts, Linux
capabilities, container entrypoint/command and security settings, namespaces,
restart/resource policy, and runtime networking. APTL lowers those compiled
fields directly into its existing typed realization boundary. It must not copy
them into a local service schema, rediscover them from Compose, or let a provider
binding silently override an authored value. An exact runtime fact that cannot
be compiled or faithfully lowered is an upstream-contract or backend-capability
gap and fails admission; it is not filled from the legacy file.

The generic materialization operations required by ADR-047 are derived driver
instructions, not another desired-state schema. They may normalize an admitted
`RuntimeConfiguration` into ordered, typed package, filesystem, identity,
service-unit, and verification operations, but must retain the owning ACES
resource address and authored explicitness/provenance and travel through
`DeploymentRealizationSpec`. They must not copy ACES service-family models,
invent product-level DTOs, or become a second parser/validator. A narrow internal
materializer validation error is translated at the interpreter/admission
boundary into the existing ACES diagnostic and `LabResult` envelopes; it does
not escape as a new public exception hierarchy.

A source/provider binding may supply backend mechanics intrinsic to an
addressed resource, such as generic-substrate distribution, package-repository
transport, or a provider-owned entrypoint/readiness mechanism. Per ADR-047, it
may not select an appliance image or inject undeclared scenario topology or
meaningful node state. Every steady-state container, network, volume, mount,
publication, and dependency in the effective model must be attributable to an
addressed compiled resource. A bounded one-shot backend helper is allowed only
when it is mechanically derived from such a resource, project-labelled,
lifecycle-owned, represented in evidence, and excluded explicitly from
steady-state parity. A Compose profile is never permission to start an
undeclared service.

The preflight inventory makes this boundary concrete: 28 of the 30 operational
TechVault VM nodes currently have no node `source`; the active legacy stack also
contains `kali-ssh-proxy` and the one-shot `cortex-index-init` without matching
SDL nodes, and the root Compose model declares 45 top-level volumes while the
SDL addresses three persistent volumes. These are cutover gaps, not permission
to retain Compose as an implicit provider catalog. Each runtime fact used by the
admitted graph must become portable authored/compiled input or an explicit,
bounded backend-policy/provider derivation under the ownership rules above;
inactive legacy profiles do not become scenario scope merely because they
appear in the old file.

At the 2026-07-19 cutover baseline, the configured public profile set selects 32
legacy service blocks, five networks, and 41 named volumes. The SDL declares 30
VM nodes and four switches; in addition to the two undeclared services above,
the legacy-only `aptl-control` network is therefore an explicit ownership gap.
These counts are migration diagnostics, not a permanent parity schema. The
static gate must derive its expected set from the admitted graph and declared
bounded helpers, while the temporary migration comparison must account for each
of these differences rather than accepting a healthy subset.

Every effective backend field has exactly one inspectable provenance class:
author-declared ACES data, ACES-processor-derived data, an APTL backend
policy/default, or a bounded source/provider binding. Missing, ambiguous,
unsupported, or unowned fields are admission errors before side effects. APTL
must not widen its backend-manifest or SEM-218 claims beyond values that the
planner gate and `observe_realization()` can prove. If ACES lacks a portable
contract for a required exact fact, the contract is fixed upstream or the
scenario fails closed; APTL does not create a local exactness vocabulary.

### Generated-model and lifecycle contract

The standalone model is written with the containment, symlink-chain,
atomic-replacement, and permission behavior already used for generated
credentials and service config. It carries environment reference names and
classification only, preserves Compose interpolation expressions, and is
validated with interpolation disabled. Resolved secret values, private keys,
tokens, generated sensitive config, raw backend output, and credentials never
enter realization DTOs, process argv, logs, diagnostics, API envelopes,
snapshots, or run records.

Rendering and validation are pure, pre-mutation admission work. The backend
stages a complete model and non-secret identity, validates every referenced
artifact declaration/source, planned output path, and backend field, then
atomically publishes the admitted lifecycle artifact before creating or
changing images, volumes, networks, content, or accounts. Generated outputs are
verified after materialization and before their consumers start. Validating only
immediately before `compose up` is insufficient if an earlier realization step
already mutated the Docker daemon or project files.

Per-project lifecycle mutation is serialized so concurrent start/stop/kill or
monitor actions cannot replace the fixed-path artifact underneath one another;
promote and reuse the existing `.aptl/lifecycle/.lock` single-owner convention
from `src/aptl/core/lifecycle_enforce.py` so manual, API, scheduled, validation,
retry, and emergency paths share one project/backend owner. Do not add a second
lock namespace around only the generated file. The lock implementation must
remain effective across processes on every supported host; the current Windows
in-process fallback is not sufficient protection for a fixed lifecycle
artifact.

Before `compose up`, backend-owned validation covers the complete standalone
model: Compose shape, generic-substrate trust and build containment, generated
bind sources, mount destinations and access, Linux capabilities/security
options, dependency closure, health/readiness definitions,
network/IPAM/internal policy, static attachments, named-volume
ownership/lifecycle, and host-published ports. An
authored exact host port fails on conflict; it is not silently remapped. An
omitted host address remains loopback by default. An SSH backend fails before
side effects while it cannot materialize project-local artifacts safely.

High-impact host/runtime powers require explicit, inspectable ownership and a
fail-closed policy: Docker-socket/control-interface mounts, host devices or
namespaces, `privileged`, unconfined seccomp, and added Linux capabilities are
never inherited from the old Compose service. Build context and Dockerfile
paths are project-contained and symlink-safe, image inputs remain subject to the
existing trust/digest policy, and secret values are not accepted in build args.
Provider policy may allow only the minimum mechanics intrinsic to the addressed
resource and must preserve read-only access where the contract requires it.

The generated artifact and its non-secret deployment digest are the lifecycle
identity for every operation. The same admitted artifact drives up, readiness,
inspection, retry, stop, kill, and volume-aware cleanup. If it is absent or
invalid, recovery may use only project/realization labels and bounded backend
metadata; it must never infer broad deletion from daemon-wide names or prefixes.
Run evidence records the execution-plan identity, typed realization digest,
field/resource provenance, and observed state through `LocalRunStore` and
`RangeSnapshot`, not a secret-bearing interpolated model. `selected_profiles`
is compatibility evidence, not TechVault realization evidence.

### Parity and cutover proof

Parity is a two-boundary proof, not a resurrected inventory. The static gate
proves that the operational SDL parses, compiles, plans, passes manifest and
SEM-218 checks, lowers every supported addressed resource to the typed
realization, renders a complete standalone model, contains no unowned
steady-state object, and does not consult the legacy Compose model. Unsupported
or no-op resources are errors for the full TechVault gate. This gate is
scenario-generic and blocking for the cutover.

The static gate's `_NoStartBackend` remains a conformance harness only. Its
simulated read-back may exercise ACES envelope plumbing, but cannot prove that a
package, filesystem entry, identity, service unit, mount, dependency, health
contract, content item, or account has a real backend consumer. Static cutover
proof comes from complete lowering plus standalone-model rendering/validation
and explicit consumer coverage; live read-after-write supplies realization
proof. A stub that echoes the requested graph is not acceptance evidence.

The live gate exercises the public clean boot (`aptl lab stop -v && aptl lab
start`) and compares project-labelled observed containers, networks,
attachments, mounts, ports, volumes, health, content, and accounts with the
admitted graph and its declared backend helpers. It retains authenticated Wazuh
readiness and a post-trigger, correlated alert assertion. A healthy subset, a
profile list, or silently started extra services is failure. The old fixed
Compose model may be a temporary migration oracle, but neither it nor a shell
provisioning-script regex remains a permanent authority or parity gate.

The whole-repository cutover boundary includes the public CLI/API orchestration
in `src/aptl/core/lab.py`, ACES catalog/plan/realization code under
`src/aptl/backends/`, Compose rendering and lifecycle under
`src/aptl/core/deployment/`, config/env/credentials/certificates/host-port
owners under `src/aptl/core/`, run evidence and endpoint discovery, the static
and live TechVault gates, package/lab asset discovery (`hatch_build.py`,
`src/aptl/_asset_manifest.py`, and `src/aptl/core/assets.py`), and all tests and
operator documentation that currently parse or describe the root Compose file
as an input. The canonical asset manifest and scenario catalog replace Compose
as package-root and bundled-asset discovery inputs; a retained derived Compose
file is reference output only.

## Security Layers

| Layer | Requirement |
| --- | --- |
| Control-plane auth gate | Existing CLI and authenticated API lab-start paths converge on the same orchestration. FastAPI router dependencies in `src/aptl/api/main.py` / `src/aptl/api/deps.py` and the BFF Host, same-origin/CSRF, cookie-plus-header session checks in `src/aptl/api/middleware/bff.py` remain mandatory; stateful realization adds no endpoint, token path, or auth bypass. |
| ACES parser and compiler gate | Authored scenarios enter through `aces_sdl.parse_sdl_file` and compile through the ACES compiler and planner. APTL does not structurally revalidate ACES SDL or recompile the `RuntimeModel` with local models. |
| Realization requirement gate | SEM-218 open and closed semantics are enforced by the ACES planner's `realization_support_diagnostics` against APTL's `RealizationSupportDeclaration`. APTL reads `realization_requirements`; it does not re-derive explicitness classes locally. |
| Runtime observation gate | `observe_realization()` emits concern values only from project-scoped backend read-back, using ACES's `CONCERN_PAYLOAD_PATH`. Missing, malformed, timed-out, or mismatched evidence omits the concern and lets `RuntimeManager.apply()` fail an exact requirement closed; it never falls back to planned payload values. |
| Deployment boundary gate | Curated compatibility paths outside operational TechVault may still drive `DeploymentBackend.start_lab` with profiles. The paper and operational TechVault scenarios drive typed `DeploymentBackend` realization methods, with Compose rendering confined to that backend. No ACES adapter code calls raw Docker, `docker compose`, or parses compose output directly (ADR-037). |
| Generic substrate and software-source gate | Per ADR-047, a node's substrate resolves only from its declared OS family/version through a small, fixed, scenario-independent base-image policy. A node `Source`, provider binding, Compose service, or scenario name cannot select an appliance image that carries scenario-meaningful state. The base image and declared package/software sources pass the existing trust/digest policy before backend side effects; unsupported OS/package-manager combinations fail admission through existing ACES diagnostics without echoing registry credentials, package credentials, build inputs, or backend stderr. |
| Network topology gate | Network creation, IPAM, `internal` egress policy, and per-node attachments come from typed realization specs. Backend validation parses CIDR/gateway/static IP values, preserves project scoping, labels backend-created networks, and fails closed before side effects when authored exact/constrained values cannot be honored. |
| Content placement gate | Operational TechVault content must be bounded inline text, project-contained checked-in file source, or project-contained checked-in directory source lowered into typed backend placement input. Path containment, safe relative-path validation, project-scoped volumes/copies, and redacted backend failures reuse existing deployment and seed precedents; captured runtime content is rejected. |
| Stateful prerequisite gate | ACES shape/reference/dependency/SEM-218 checks precede backend policy validation of artifact providers, contained outputs, complete certificate sets, cryptographic relationships, mount sources/destinations, stable project-scoped volume identities, lifecycle, and local/SSH feasibility. Generated overrides are rechecked after materialization and before startup; observed mounts, authenticated Wazuh readiness, and actual alert retrieval are required runtime evidence. |
| Artifact path and permission gate | Manager configuration and certificate outputs reuse `credentials.py` containment, symlink-chain rejection, atomic replacement, and verified mode behavior. Declared certificate outputs additionally pass key-pair, CA-chain, subject/SAN, consumer, and completeness checks. No unchecked path, missing output, or warning-only permission failure reaches Compose. |
| Effective Compose model gate | The backend renders and validates one standalone model, generated bind sources, volume declarations, dependency order, loopback publications, and health contract before `compose up`. Validation preserves secret references and runs without interpolation; it neither logs nor persists a fully interpolated model. An overlay/base merge, partial reset, or inherited hand-authored semantic is a cutover failure. |
| Account placement gate | ACES parser/compiler, canonical account-feature extraction, manifest capability checks, and SEM-218 explicitness/provenance run before the backend. The backend resolves the placement only through its typed target node, validates the full batch and provider syntax before mutation, then creates/reconciles groups and accounts after bounded provider readiness and verifies non-secret state. Raw credentials, hashes, provider stderr, and caller-supplied container identities remain outside typed inputs and evidence. |
| Config, env, and secret binding | Non-secret backend/admission knobs bind through strict `AptlConfig`; config toggles do not add or remove operational TechVault topology. Runtime secrets pass through `hydrate_dotenv`, `load_dotenv`, `env_vars_from_dict`, `find_placeholder_env_values`, and `EnvVars`, while the graph carries only secret-reference names and classification. Values resolve only at the existing renderer/provider/readiness boundary and are passed through the existing env or permissioned-file channels. Hard-coded collector defaults are not a live credential source. The realization record stores digests and non-secret identities, never `.env` values, rendered config, tokens, or key material. |
| Host and process exposure | Existing loopback host-binding policy and published-port conflict checks apply to Wazuh. Docker/Compose execution uses argv lists through the shared local/SSH runner; credentials, private-key contents, and rendered config are never command arguments. An unclassified host bind or a remote artifact path the backend cannot materialize fails closed. |
| Logging and error envelope | Provider failures collapse into bounded, stable `LabResult`, existing deployment exceptions, and ACES diagnostics after shared redaction. Raw subprocess stdout/stderr, SDL secret values, rendered config, private keys, and raw alert bodies do not cross logs, API responses, telemetry, snapshots, or run artifacts; no Wazuh-only exception hierarchy is introduced. |
| Persistence and redaction | Realization details, selected profiles only for compatibility scenarios, typed realization digests/provenance for dynamic scenarios, and evaluator-only evidence enter JSON through `LocalRunStore` and `RangeSnapshot.to_dict()`, inheriting ADR-029 redaction and path-containment checks. Neither interpolated Compose nor secret-bearing generated configuration is evidence. |
| Static and live validation gate | Static tests prove the SDL parses, plans, and lowers to a complete standalone realizable model without unsupported, unowned, or no-op resources, and without a legacy Compose input. The live gate remains a public clean `aptl lab stop -v && aptl lab start` plus graph-to-observation parity, authenticated readiness, and correlated evidence, not a comparison to captured inventory state. |

## Maintainability

The canonical incumbents this decision builds on are:

- `src/aptl/backends/aces.py` for the `RuntimeTarget` wiring and
  `AptlProvisioner`.
- `src/aptl/backends/aces_realization.py` and
  `src/aptl/backends/aces_realization_model.py` for the interpret stage and its
  typed output.
- `src/aptl/backends/aces_materializer.py` for ADR-047's pure,
  product-agnostic lowering from admitted ACES runtime state to ordered typed
  driver operations. Its operation values are derived instructions carried by
  the deployment realization, not a local runtime/service schema and not a
  public exception boundary.
- `src/aptl/backends/aces_profiles.py` for curated compatibility only. It is
  not the paper-scenario or operational-TechVault topology driver.
- `src/aptl/backends/aces_diagnostics.py` for the supported-resource-type set
  and diagnostics.
- `src/aptl/backends/aces_observation.py` for backend evidence-to-concern
  translation, using the ACES-owned concern path registry rather than an
  APTL-local schema.
- `src/aptl/backends/aces_manifest.py` for the realization support declaration.
- `src/aptl/backends/aces_observation.py` for explicit backend-observed
  realization state; new resource kinds must not fall through to placement
  observation.
- `src/aptl/api/main.py`, `src/aptl/api/deps.py`, and
  `src/aptl/api/middleware/bff.py` for control-plane authentication, Host,
  same-origin/CSRF, and two-factor browser-session enforcement. Realization
  remains behind the existing lab-start surface.
- `aces_backend_protocols.account_features.provisioner_account_features` for
  the governed account-spec-to-feature mapping; do not copy that decision table
  into APTL.
- `src/aptl/core/deployment/` for every Docker, Compose, container, and host
  operation, including any future image pull/build/tag and network/IPAM side
  effects.
- `src/aptl/core/scenario_catalog.py` for registered scenario identity and
  project-contained resolution, and `src/aptl/core/lab.py` for the one public
  CLI/API orchestration and retry boundary. Neither gains a second SDL planner.
- `src/aptl/core/credentials.py` and ADR-028 for contained, atomic manager
  configuration rendering; `src/aptl/core/certs.py` and `config/certs.yml` for
  the existing Wazuh certificate generator/subject contract. These are
  providers behind typed realization, not competing workflow authorities.
- `src/aptl/core/deployment/realization.py` and
  `src/aptl/core/deployment/_compose_realization.py` for the typed realization
  DTO and its ordered backend-owned side effects; do not create a Wazuh
  orchestrator beside them.
- `src/aptl/core/deployment/_compose_port_realization.py` for typed host-port
  exposure decisions and conflict validation. The image-pull/build behavior in
  `src/aptl/core/deployment/_compose_image_realization.py` is compatibility code
  superseded by ADR-047 for operational TechVault; reuse only generic image
  trust/digest mechanics that apply to the fixed base substrate, never its
  appliance-image or overlay/base assumptions. Move rendering behind the
  standalone Compose-model boundary; existing overlay/base merge behavior is
  not a cutover contract. Apply ADR-028 containment, symlink, atomic-write,
  permission, and effective-model validation rather than copying unchecked
  file-write details.
- `src/aptl/core/seed_spec.py` and existing named-volume seed behavior for
  project-contained source-to-runtime materialization when content placement
  needs file or directory side effects. Mutable Wazuh persistence reuses its
  project-scoping and runner conventions, not its seed semantics.
- `src/aptl/core/services.py`, `src/aptl/utils/curl_safe.py`,
  `src/aptl/core/collectors.py`, and
  `src/aptl/validation/techvault_live_gate.py`,
  `src/aptl/validation/_live_gate_checks.py`, and
  `src/aptl/validation/_live_gate_probes.py` for shared readiness polling,
  argv-safe authentication, Wazuh alert collection, and the clean-start live
  evidence gate. The manager probe must use the deployment backend and gain an
  authenticated readiness check; its current raw, status-only probe and the
  live gate's Suricata-or-Wazuh success condition are not incumbents to copy.
- `src/aptl/core/runstore.py`, `src/aptl/core/snapshot.py`,
  `src/aptl/core/config.py`, and `src/aptl/core/env.py` for run persistence,
  inventory evidence, config, and env binding.
- `src/aptl/_asset_manifest.py`, `src/aptl/core/assets.py`, `hatch_build.py`,
  and `scenarios/catalog.json` for package assets and lab-root/scenario
  discovery. Compose is removed as an input/marker rather than replaced by a
  second generated asset list.
- `src/aptl/utils/redaction.py`, `src/aptl/core/lab_types.py`, and
  `src/aptl/core/deployment/errors.py` for redaction and the existing result /
  timeout/failure envelopes; do not add Wazuh-specific copies.
- `scenarios/paper-agent-loop.sdl.yaml` for #579's manager/indexer and Wazuh
  evidence contract; `scenarios/techvault-operational.sdl.yaml` for dynamic
  public startup; and `scenarios/catalog.json` for their registered selection.

Tests extend the existing ACES backend and realization seams
(`tests/test_aces_backend.py` and the realization-focused tests) rather than
introducing a new harness.

## Extensibility

The extensibility seam is the boundary between the interpreted realization and
the driver. Interpret produces a typed `AptlRealization` from the compiled plan;
the compatibility driver may map explicitly compatible scenarios onto profiles.
The paper and operational TechVault drivers consume the typed realization spec
directly through `DeploymentBackend`. Standalone rendering is parameterized by
execution-plan identity, `DeploymentRealizationSpec`, backend/provider policy,
project identity, and target capability. A new authored resource type extends
`SUPPORTED_RESOURCE_TYPES`, the interpreter, and a typed backend operation when
runtime side effects are needed, without adding a second topology authority or
branching on a specific scenario name.

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

For ADR-047 node materialization, the extensibility seam is the tuple of
declared OS family/version, fixed generic-substrate policy, compiled
`RuntimeConfiguration`, ordered typed materialization operations, backend
provider/target capability, and read-after-write observations. The next likely
change is another OS family or package manager, multi-architecture generic base
selection, package-repository authentication, or SBOM/attestation policy. Those
extend the fixed policy map or typed operation/provider boundary; they do not
restore ACES `Source`, Compose service identity, or scenario names as appliance
image selectors, and they do not add product-named materializer branches.

For content and account realization, the seam is a typed placement record:
ACES placement address, target node/service/container, content or account
identity, non-secret provenance, bounded source kind, destination kind, and the
backend materialization operation. Account provider kind is resolved from the
typed target binding, not from scenario identity. Future scenarios should be
able to vary which checked-in source directory, inline file, target node,
account fixture, or provider backend is used without editing TechVault-only
code. Future account deletion/replacement reuses ACES `ChangeAction`; it must
not add an APTL-only lifecycle enum.

For generated artifacts and stateful storage, the seam is the addressed
realization graph described by the heavy-service addendum. Provider kind,
target, dependency addresses, output/consumer identity, sensitivity,
mount/access contract, persistence lifecycle, secret references, and provenance
are parameters. Raw commands and Compose fragments are deliberately not
extension points.

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

- The standalone renderer and lifecycle metadata become a versioned backend
  contract. Field provenance, deterministic output, project labels, and
  backward-compatible cleanup must stay aligned across local and SSH targets.
- APTL's realization support declaration must stay honest. Widening the claimed
  realization support without the interpreter and driver to back it would let
  the planner gate pass scenarios APTL cannot actually realize.
- The honest TechVault SDL may be smaller than the captured inventory. Omitting
  non-realizable captured facts is correct; carrying them as no-op operational
  placements is not.

### Risks

- An authored scenario can carry resource types APTL does not interpret.
  Compatibility scenarios may continue to report bounded diagnostics, but the
  full operational TechVault gate treats every unsupported or no-op addressed
  resource as a pre-side-effect error.
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

- This ADR does not replace Docker Compose as a deployment backend. It does
  replace the repository-root, hand-authored `docker-compose.yml` as the
  operational TechVault realization and lifecycle input; any retained copy is
  deterministic derived/reference output.
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
- Issue #579 by itself did not dynamically realize the dashboard, merge the
  Wazuh and lab SOC certificate authorities, design certificate rotation,
  capture or seed mutable Wazuh data, migrate existing volumes, change Wazuh
  versions or credentials, add remote artifact synchronization, or introduce a
  generic init-job/workflow or evaluator engine. It may sequence the existing
  action, evidence probe, and `AptlEvaluator` result correctly for Wazuh, but it
  does not create a parallel evaluation contract. An SSH realization may remain
  explicitly unsupported until the backend can materialize its artifacts
  safely.
- Issue #581 does not create a new orchestration language, generic provider hook
  or command schema, Kubernetes backend, remote artifact synchronization, API
  endpoint, auth model, secret store, transactional rollback, or daemon-wide
  cleanup mechanism. It does not promote services from inactive legacy Compose
  profiles into TechVault merely because they existed in that file; the
  operational SDL decides membership, while every service selected by the
  pre-cutover canonical public start must be accounted for as an addressed
  resource or an explicitly bounded backend helper.
- Issue #692 does not add a second disclosure gate, a new runtime snapshot or
  evidence schema, an API surface, operator-configurable probe commands,
  content equality/integrity attestation, or transactional provisioning
  rollback.

## Anti-Patterns

- Treating a scenario name as a profile selector instead of deriving profiles
  from the interpreted realization.
- Reading the repository-root `docker-compose.yml`, `ComposeProfileIndex`, or
  `aptl.json` container switches to complete operational TechVault topology,
  service identity, or lifecycle behavior missing from the admitted graph.
- Producing the standalone model by copying legacy Compose service blocks and
  labelling the result "generated" without typed field ownership and
  provenance.
- Re-planning the SDL in artifact preparation, host-port resolution, retry,
  validation, or evidence code instead of consuming the single admitted
  execution/realization identity.
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
- Encoding generated config, certificate/key bundles, or mutable persistence as
  content placement; treating the ambiguous raw `runtime.mounts` payload as a
  locally authoritative desired-volume schema instead of consuming an upstream
  compiled contract; or adding an APTL-local stateful-service schema while ACES
  lacks that contract.
- Claiming Wazuh realization because the `wazuh` profile or a hand-authored
  Compose service started, a plan resource was echoed into a snapshot, or only
  `root-ca.pem` exists.
- Adding a generic `run`/hook/command field, invoking a provider-specific shell
  fragment from SDL, or copying Wazuh lifecycle ordering outside
  `DeploymentBackend`.
- Assuming the base-file bind-mount scan covers generated overrides, that local
  files are visible to an SSH Docker daemon, or that the operational SDL's
  reverse manager/indexer dependency is valid boot ordering.
- Using a partial Compose overlay that silently retains base mounts,
  environment, dependencies, healthchecks, or commands, or relying on a
  reset/override merge tag without enforcing its supported Compose version.
- Interpolating secret values into the generated model, passing them on process
  argv, or persisting/logging the rendered effective configuration as proof.
- Treating container health, node-ready evaluator conditions, authored evidence
  intent, or a Suricata-only event as proof of a functioning realized Wazuh.
- Using the collector's default credentials, accepting any alert already in the
  index, evaluating the Wazuh condition before its trigger, or recording a
  Wazuh count without a bounded non-secret correlation to the triggering action.
- Recreating named volumes on every start, using unscoped/global or random
  volume names, inferring deletion from absence, or modeling mutable Wazuh state
  as a named-volume seed.
- Starting with a generated effective Compose model but stopping with only the
  base file when that can leave realized containers, networks, or volumes
  orphaned.
- Treating a profile set, selected-container subset, or healthy declared nodes
  as full parity without rejecting extra project-labelled steady-state runtime
  objects and missing mounts, publications, volumes, or dependencies.
- Logging or persisting PEM/key material, rendered configuration, resolved env
  secrets, raw alert bodies, or backend stderr; accepting incomplete cert
  output, failed permission repair, or unchecked key/certificate/SAN/chain
  relationships as success.
- Running both the generic lab-start cert/config preparation and typed
  realization for the same manager/indexer artifacts.
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
- [ADR-028](adr-028-runtime-rendered-service-config.md): contained, atomic,
  redacted service configuration rendering.
- [ADR-034](adr-034-lab-managed-soc-tls-ca.md): SOC CA ownership and its
  explicit separation from the existing Wazuh certificate chain.
- [ADR-043](adr-043-suricata-runtime-config-ownership-boundary.md): named-volume content
  seeding precedent and the boundary between static content and mutable state.
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
  [#579](https://github.com/Brad-Edwards/aptl/issues/579),
  [#581](https://github.com/Brad-Edwards/aptl/issues/581),
  [#689](https://github.com/Brad-Edwards/aptl/issues/689),
  [#692](https://github.com/Brad-Edwards/aptl/issues/692),
  [aces#598](https://github.com/Brad-Edwards/aces/issues/598), and
  [aces#600](https://github.com/Brad-Edwards/aces/issues/600); DSL-008 /
  [#422](https://github.com/Brad-Edwards/aptl/issues/422).
