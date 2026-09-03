# ADR-051: Component-Level RAES Realization

## Status

accepted

## Date

2026-07-28

## Context

APTL dynamically realizes `scenarios/techvault-operational.sdl.yaml` through
the RAES parse, compile, plan, apply, and observation pipeline established by
[ADR-046](adr-046-dynamic-raes-scenario-realization.md). ADR-048 then required
every scenario-meaningful node to be materialized onto a generic operating
system base and prohibited component images.

That prohibition confuses two different authorities:

- an image can own the distributable software and invariant startup mechanics
  of one component; and
- RAES must own which components exist, their topology, effective
  configuration, identities, seeded scenario content, persistence, telemetry,
  integrations, and acceptance criteria.

The last Compose TechVault before generic materialization, commit
`304d1217f72d053b0e4201844eb731d5f513e24a`, used both upstream images and
individual component builds. Replacing a complex product with a generic
container that has the expected name or a few packages does not preserve its
behavior. It creates a hollow node while allowing the deployment to appear
successful.

RAES already has the contracts needed to make source choice explicit and
verifiable:

- `Source.artifact_requirement` and `artifact-requirement-v1`
  (`raes.artifact_requirements`);
- `ArtifactMechanismCapability`, `ArtifactAvailabilityContext`, and
  `ArtifactSatisfactionDisclosureModel` (`raes_contracts.artifact_requirements`);
- `artifact_requirement_diagnostics()` and `evaluate_artifact_realization()`
  (`raes_processor.semantics.artifact_realization`);
- `RuntimeConfiguration` for effective runtime state;
- `RealizationDesignation` and `CompiledRealizationRequirement` for
  closed/open realization posture; and
- planner artifact admission plus runtime non-approximation checks.

### Verified state at the time of this decision

Measured against the pinned RAES 2.0.0 and the parity baseline `304d1217`:

- No SDL node carries `artifact_requirement`. The `sha256:…` values live in
  `source.version`, and ADR-098 §2.1 states a selector is not integrity
  evidence. `_ALLOWED_DIGEST_SOURCE_NAMES` reinterprets a selector as exact
  evidence, which that section forbids.
- `wazuh-manager` declares `version: 4.x`; `_ALLOWED_SOURCE_IMAGE_REFS` supplies
  `wazuh/wazuh-manager:4.12.0` from APTL code, so the SDL never names the artifact.
- APTL's manifest declares `artifact_mechanisms = ()` and `CONSTRAINED`. Because
  `_artifact_route_diagnostics` derives its supported-route set from that field,
  every artifact requirement would fail `artifact.unsupported-backend-mechanism`
  in any posture, and no open concern is admissible.
- APTL calls `RuntimeManager.plan()` with no `ArtifactAvailabilityContext`.
- The scenario declares no `realization:` table, so every scope resolves
  `CLOSED_WORLD` and undeclared runtime state is already inadmissible.
- The generic-materialization conversion dropped 20 volumes and 38 environment
  variables across eight nodes without re-declaring them, including `webapp`'s
  entire database binding and `misp-suricata-sync`'s MISP API wiring. That is the
  hollow-node failure mode this decision exists to make impossible.

APTL also already has the backend seams needed to execute an admitted choice:
`DeploymentImageRealization`, `DeploymentNodeRealization`,
`DeploymentRealizationSpec`, the generic materializer, and
`DeploymentBackend`.

## Decision

RAES remains the scenario and topology authority. APTL realizes every VM node
through exactly one admitted component source route and verifies the complete
node contract before reporting the resource ready.

### Source routes

The source route is expressed with the existing RAES artifact contracts, not
an APTL-local `source_type` enum.

1. **Pinned upstream or vendor artifact.** Use an exact artifact requirement
   and an `exact-artifact` pull route. The immutable identity includes a digest;
   a mutable tag, a product name plus `4.x`, or an APTL allowlist entry alone is
   not an admissible pin.
2. **Purpose-built component artifact.** Use a digest-bound
   `materialization-specification` route with verified locked inputs,
   associated artifact manifests, and trust/provenance references. The build
   produces one component image. `Source.build` remains observed provenance
   and must not be reinterpreted as executable build instructions.
3. **Generic runtime composition.** Use a `dynamic-composition` route over a
   pinned generic substrate. This route is admissible only when the compiled
   declarations completely state every applicable component-contract
   dimension and the backend declares that it can materialize and independently
   read back each one.

Switch nodes are realized as networks through the existing network concern and
do not select a container artifact.

#### Route 3 realized artifact satisfaction

A successful route-3 realization discloses the generic substrate, not a
fictional image containing the composed node. The existing RAES
`ArtifactSatisfactionDisclosureModel` carries:

- an `ArtifactIdentity` for the selected generic-substrate policy variant whose
  digest is the image identity verified on the target daemon;
- `mechanism: dynamic_composition_profile()`;
- `acquisition: local-lookup` and `timing: realization`;
- `integrity_refs` containing exactly that verified substrate digest; and
- `provenance_refs` containing
  `dynamic_composition_provenance_ref()`.

The artifact identity uses a stable generic-substrate policy identity and a
truthful media type. It does not reuse `Source.name`, a Compose service, a node
address, a registry/repository location, a mutable tag, or the scenario-bundle
path as portable identity. The installed packages, configuration, identities,
ports, mounts, capabilities, agents, and listeners remain separate runtime
concerns proved through the ordinary concern registry; the substrate digest
does not claim that those effects are baked into the image.

Before planning, APTL resolves the same fixed base-substrate policy that
`base_container_spec()` uses for realization and asks the typed deployment
backend for the immutable identity and local start reference available on the
target daemon. The address-scoped `ArtifactRequirementAvailability` verifies
both the digest and the dynamic-composition provenance reference. Realization
starts that immutable local identity, not the mutable selector used to find it.
An absent, changed, malformed, ambiguous, wrong-platform, or otherwise
unresolvable substrate yields no verified claim or container and must not fall
through to a registry pull during the declared `local-lookup` route.

Availability and post-realization readback use one digest domain. In
particular, an OCI manifest digest and a Docker image/configuration ID are not
interchangeable merely because both start with `sha256:`; the disclosed media
type must describe the bytes the digest identifies. The runtime gate compares
the digest observed from the container with the verified availability facts.
The independent readback remains a defense-in-depth check: any backend mismatch
fails closed and retains the baseline snapshot.

### Authored posture binds the backend

Route selection is not an APTL policy choice. RAES `SEM-218` and ADR-098 make the
authored explicitness class binding, and APTL honors it:

- **`exact`**: the requirement names one digest-bound `ArtifactIdentity` and
  permits only the `exact-artifact` mechanism. APTL MUST obtain exactly that
  artifact or reject. It MUST NOT fall back to another digest, rebuild the
  artifact, substitute a compatible version, or reinterpret a selector as exact
  evidence (I1, I2; ADR-098 §2.1).
- **`constrained`**: APTL MUST select only a declared, available candidate or a
  digest-bound materialization specification within the authored domain, and MUST
  disclose the selected id. Candidate order is not fallback order.
- **`open`**: APTL MAY select only where its manifest declares
  `support_mode: open-realization` with a matching mechanism route, and, when a
  finer realization envelope is published, only where the offered projection
  subsumes the compiled open request (I3).

`OPEN_REALIZATION` in one domain is never permission to ignore an exact
declaration in that same domain.

Planning admission determines the eligible route set by intersecting the authored
permitted routes, trusted address-partitioned `ArtifactAvailabilityContext` facts,
and the manifest's `artifact_mechanisms`. Only when more than one route survives
that intersection does a deterministic, backend-owned preference policy choose
among them; that policy is keyed by mechanism and profile, never by scenario name,
node name, Compose service, or local cache contents. The selection carries through
the existing typed realization objects.

APTL declares a mechanism in its manifest only after it can both materialize and
independently read back that mechanism's effects (I4). Capability disclosure
follows implementation; it never anticipates it.

Realized values are recorded with author-declared, processor-derived, or
backend-realized provenance on the existing `RealizationProvenanceEntry` ledger
(I5). Exact satisfaction retains `author-declared`; backend selection on an
admitted constrained or open surface is `backend-realized`. The returned runtime snapshot
must disclose the selected route using `ArtifactSatisfactionDisclosureModel`;
RAES performs the final non-approximation check.

No source route is inferred from a node name, scenario name, Compose service,
the mere presence of `runtime`, or a local image cache.

### Complete component contract

Every VM node, including a node backed by a vendor image, must have a closed
runtime contract covering:

- operating system and immutable component artifact;
- packages, applications, and component software;
- service processes, listeners, startup order, and readiness;
- local users, groups, domain identities, and application authorization;
- seeded files, directories, configuration, and scenario content;
- network attachments, addresses, host publications, DNS, and ACLs;
- persistent and ephemeral state, mounts, ownership, and reset lifecycle;
- telemetry producers, forwarding, evidence boundaries, and health signals;
- dependencies and integrations with other addressed components; and
- resource, capability, and container security requirements.

An applicable dimension may be explicitly empty. Omission is not evidence that
the dimension is satisfied. APTL must not create a parallel component-contract
DTO or copy the RAES runtime schema.

#### Where the contract is enforced

RAES 2.0.0's compiler lowers only five things into
`CompiledRealizationRequirement`: `source.artifact_requirement`,
`generated_artifacts.<n>`, `persistent_volumes.<n>`,
`identity_domains.<d>.topology`, and `content.<n>.service_materialization`. It does
not yet lower `runtime.environment`, `runtime.mounts`, `runtime.service_listeners`,
`runtime.linux_capabilities`, published ports, `forwarding_agents`, or
`identity_authorities`. Two consequences follow.

First, a genuinely stateful mount is declared as a `persistent_volume` rather than
a `runtime.mount`, because that is the form RAES admission actually enforces.

Second, APTL owns the contract-completeness gate for the dimensions RAES does not
lower. That gate is per node and per dimension, and each dimension it admits must
be backed by read-after-write evidence. It is never an APTL-local "complete"
boolean, an optimistic manifest declaration, or a count of declared fields.
Widening the RAES realization registry so these fields become enforceable demand is
upstream work against `Brad-Edwards/aces`; until it lands, the ownership above is
explicit rather than assumed.

> **Update (2026-07-30, issue #876).** That upstream work has landed. raes 3.1.0
> (OpenRAE/rae#985) lowers `runtime.environment`, `runtime.mounts` (bind/tmpfs),
> `runtime.linux_capabilities`, `runtime.network.published_ports`,
> `runtime.forwarding_agents`, and `runtime.service_listeners` into the SEM-218
> realization concern registry, so RAES now owns their admission
> (`realization_support_diagnostics`) and their fail-closed non-approximation gate
> (`realization_disclosure`). The backend-owned contract-completeness gate this
> section describes is therefore superseded for those dimensions by the ordinary
> observe-and-disclose path: APTL reads each declared concern off the realized
> container through the typed `DeploymentBackend` and discloses the observed value
> at the concern's payload path, projected through RAES's own registry projector
> (with its secret-boundary value commitment); the observer is
> `aptl.backends.raes_runtime_observation`. A declared concern APTL cannot observe
> is omitted from the returned snapshot, so an EXACT declaration is still rejected;
> the fail-closed outcome is unchanged, now enforced by RAES. APTL advertises the
> `dynamic-composition` mechanism (`OPEN_REALIZATION`, `local-lookup`/`realization`)
> on the strength of that readback. The route-3 *source-artifact* satisfaction
> (disclosing the realized generic substrate digest) is implemented in the same
> change, on top of the merged #874 / PR #891 realization roots, per the "Route 3
> realized artifact satisfaction" section above.

A running container, an installed package, an open port, or a matching name
proves only that individual fact. Readiness requires all admitted facts and
component-specific semantic probes to pass. A generic route with an incomplete
contract fails before backend mutation.

### Image and runtime ownership

An upstream or purpose-built image may own component software and invariant
entrypoint mechanics. It must not own the TechVault scenario.

RAES owns runtime composition: selected nodes, topology, effective
configuration, network wiring, credentials by reference, generated artifacts,
participant and seeded content, accounts, persistence, telemetry, integration
bindings, and readiness expectations. A per-component image must remain useful
outside TechVault when given different runtime inputs.

Vendor security applications are therefore valid component artifacts. Wazuh,
MISP, TheHive, Cortex, Shuffle, Suricata, and their datastores may use pinned
upstream images while their certificates, credentials, rules, integrations,
volumes, network placement, startup dependencies, and authenticated readiness
remain RAES/APTL runtime-owned. This does not permit a whole-range image or an
image containing prewired TechVault topology.

### Backend and failure boundary

All Docker operations remain behind `DeploymentBackend`. The local packaged
Docker path used by `aptl lab start` is the canonical target.

An unsupported, unavailable, untrusted, incomplete, or unverifiable source
route is a fatal admission or realization error:

- before mutation, return stable RAES artifact or provisioner diagnostics;
- after mutation, return an unsuccessful `ApplyResult`, do not publish the node
  as ready, and use the existing scoped cleanup path; and
- project the failure through `LabResult` and the existing CLI/API error
  envelopes. It is not a degraded-readiness warning.

Partial realization never satisfies the plan. Runtime evidence records
non-secret artifact identity, selected mechanism, digests, and proof
references, never credentials or rendered secret-bearing configuration.

## Consequences

### Positive

- Complex vendor products retain honest component behavior without moving
  scenario authority out of RAES.
- Simple components can still prove genuine generic composition.
- Artifact selection, supply chain admission, and runtime satisfaction reuse
  RAES contracts across backends.
- Per-component images preserve meaningful service and security boundaries
  without creating a monolithic range artifact.

### Negative

- Every TechVault node needs a complete authored runtime contract even when an
  image supplies its software.
- APTL must publish honest artifact mechanism support and produce satisfaction
  evidence.
- Some current generic nodes and source-only vendor nodes will fail the stricter
  admission gate until their missing contracts are authored and observable.

## Supersession

This ADR supersedes ADR-048's requirement that all scenario-meaningful software
be installed onto a generic base and its prohibition on component images.
ADR-048's placement, fail-closed readback, no-scenario-branch, Docker-local,
bidirectional parity, and no-whole-range-image guardrails remain in force.

ADR-046 remains authoritative for the RAES authority chain, typed
interpretation, deployment backend boundary, run evidence, and lifecycle.

## Non-Goals

- A monolithic TechVault or whole-range image.
- Kubernetes, cloud provisioning, nested virtualization, or an appliance
  requirement.
- Treating the pre-refactor Compose file as a runtime input.
- Encoding credentials, topology, participant content, or scenario wiring in a
  component image.
- Replacing RAES artifact, runtime, diagnostic, snapshot, or capability
  contracts with APTL-local equivalents.
