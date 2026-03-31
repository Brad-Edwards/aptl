# ADR-017: SDL Runtime Layer

**Status:** Proposed
**Date:** 2026-03-30
**Deciders:** Brad Edwards

## Context

The SDL is now the authoritative scenario specification surface. The next layer
must execute *that* model directly rather than adapting legacy scenario/runtime
code that predates the SDL.

The first runtime attempt introduced the right package boundary but the wrong
core abstraction: it treated raw SDL section entries as generic executable
steps. That collapsed reusable definitions and bound runtime instances into the
same concept, made reconciliation incomplete, and pushed too much meaning into a
single cross-domain interface.

The runtime needs to be built greenfield inside the new package boundary:

```text
aptl.core.sdl      -> specification and validation
aptl.core.runtime  -> compile, plan, execute contracts
aptl.backends.*    -> target-specific implementations
```

## Decision

Adopt a three-stage SDL-native runtime architecture:

1. **Compile** `Scenario -> RuntimeModel`
2. **Plan** `RuntimeModel + BackendManifest + RuntimeSnapshot -> ExecutionPlan`
3. **Execute** domain plans through explicit runtime target protocols

### Compiler

`compile_runtime_model()` is a pure normalization pass that separates reusable
SDL definitions from bound runtime instances.

Examples:

- top-level `features` remain templates, while `node.features` become
  node-scoped `FeatureBinding`s
- top-level `conditions` remain templates, while `node.conditions` become
  node-scoped `ConditionBinding`s
- top-level `injects` become first-class orchestration resources, while
  `node.injects` become optional node-scoped `InjectBinding`s that target those
  resources
- `nodes` + `infrastructure` become deployable network/node resources
- events, scripts, stories, workflows, metrics, evaluations, TLOs, goals, and
  objectives become resolved runtime graph nodes with canonical addresses

Bound condition refs fail closed. Unqualified condition refs must resolve to
exactly one binding; zero or multiple matches produce diagnostics instead of
implicit fan-out. Event inject refs resolve directly to top-level inject
resources and produce diagnostics when the named inject is missing.

### Planner

The planner no longer emits a flat step DAG. `ExecutionPlan` is composite:

- `ProvisioningPlan`
- `OrchestrationPlan`
- `EvaluationPlan`

Each plan operates on canonical runtime resources inside its own temporal model.
Reconciliation is explicit and complete:

- desired-only -> `CREATE`
- changed -> `UPDATE`
- snapshot-only -> `DELETE`
- identical -> `UNCHANGED`

Plans are provenance-bound to the target name, backend manifest, and base
runtime snapshot they were reconciled against.

Runtime resources carry two dependency sets:

- `ordering_dependencies` for same-domain create/start ordering and reverse
  delete ordering
- `refresh_dependencies` for downstream refresh propagation when upstream state
  changes

Cross-domain refs participate only in refresh propagation. Fixed phase order
remains `provisioning -> evaluation -> orchestration`.

### Capability Model

Capabilities are domain-specific rather than a single overloaded bag:

- `ProvisionerCapabilities`
- `OrchestratorCapabilities`
- `EvaluatorCapabilities`

The planner validates semantic requirements from the compiled model, including
node types, OS families, scaling limits, ACL usage, content types, account
features, orchestration usage, workflows, workflow predicate condition refs,
scoring, and objectives.

### Runtime Target And Registry

Backends must provide an explicit `BackendManifest`. Runtime targets are created
through a registry that separates:

- `manifest()` for capability introspection
- `create()` for backend instantiation

There is no fallback capability inference from a provisioner instance, and
`create()` must instantiate components against the same manifest returned during
introspection. Phase 1 intentionally supports at most one evaluator per target;
explicit evaluator partitioning is deferred until the runtime has a real routing
model.

`RuntimeTarget` is self-validating: manifest presence and component shape must
match both for registry-created targets and direct construction.

### Protocols

Protocols consume domain plans, not generic steps:

- `Provisioner.apply(provisioning_plan, snapshot)`
- `Orchestrator.start(orchestration_plan, snapshot)`
- `Evaluator.start(evaluation_plan, snapshot)`

Orchestrators and the phase 1 evaluator are lifecycle services with `status()`
and `stop()`. Failed runtime-service startup triggers best-effort rollback of
started services while preserving any provisioning state already applied.
Services are only started when their domain plan has operations, but delete-only
reconciliation still runs through the same lifecycle entrypoint.

Objective `window` refs remain declarative scope/refresh inputs. They do not
create cross-domain executor ordering semantics. `depends_on` remains the only
objective ordering relation.

## Consequences

### Positive

- The runtime now matches SDL semantics instead of forcing them through a flat
  step abstraction.
- Reconciliation is honest and supports deletes as well as updates.
- Capability validation can fail fast on real backend mismatches.
- Ambiguous or unbound runtime refs are rejected instead of being guessed.
- Phase 1 stubs exercise the correct contracts for future real backends.

### Negative

- The just-added runtime API is intentionally broken and replaced.
- The compiler/planner split adds more explicit types and indirection.
- Future backends must implement manifests and domain protocols from day one.
- Real scenarios must bind orchestration/evaluation refs unambiguously.

## Scope Boundaries

- This decision does **not** preserve or adapt legacy backend/runtime code.
- Phase 1 ends at compiler, planner, manager, stubs, and tests/docs.
- Real target implementations follow later on top of these contracts.
