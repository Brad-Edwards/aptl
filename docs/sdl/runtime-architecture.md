# Runtime Architecture: SDL -> Runtime Model -> Composite Plans

This document describes the runtime layer that sits directly on top of the SDL.
It is a greenfield runtime architecture built for the SDL itself, not an
adapter around any previous scenario/backend implementation. See
[ADR-017](../adrs/adr-017-sdl-runtime-layer.md) for the decision record.

## Package Boundary

```text
aptl.core.sdl      -> parse + validate
aptl.core.runtime  -> compile + plan + execute contracts
aptl.backends.*    -> concrete target implementations
```

## Runtime Stages

### 1. Compile

`compile_runtime_model(scenario)` is a pure normalization pass.

It separates reusable definitions from bound runtime instances:

- `features` -> feature templates
- `node.features` -> node-scoped feature bindings
- `conditions` -> condition templates
- `node.conditions` -> node-scoped condition bindings
- `injects` -> first-class orchestration inject resources
- `node.injects` -> optional node-scoped inject bindings layered on top of top-level inject resources
- `nodes` + `infrastructure` -> deployable network/node resources
- orchestration and scoring/objective sections -> resolved graph nodes

The output is a `RuntimeModel` with canonical addresses for every runtime-owned
object.

Bound condition refs fail closed. An unqualified condition reference must
resolve to exactly one bound runtime instance; zero matches and multiple matches
are both compile-time diagnostics. Event inject refs resolve directly to
top-level inject resources and fail if the named inject does not exist.

### 2. Plan

`plan(runtime_model, manifest, snapshot)` is also pure.

It validates semantic backend requirements and reconciles desired runtime
objects against the current `RuntimeSnapshot`.

`ExecutionPlan` is composite:

- `ProvisioningPlan` for deployable resources and bindings
- `OrchestrationPlan` for events, scripts, stories, workflows, and inject state
- `EvaluationPlan` for condition bindings, scoring graph nodes, and objectives

Each plan is provenance-bound to:

- the target name
- the backend manifest used for validation
- the base snapshot it was reconciled against

Reconciliation actions are explicit:

- `CREATE`
- `UPDATE`
- `DELETE`
- `UNCHANGED`

Runtime resources carry two dependency sets:

- `ordering_dependencies`: same-domain edges used for create/start ordering and reverse delete ordering
- `refresh_dependencies`: edges whose changes force downstream `UPDATE`

Cross-domain refs participate in refresh propagation, but not startup ordering.
This keeps the fixed phase order intact while still making downstream plans
honestly react to upstream changes.

## Runtime Snapshot

`RuntimeSnapshot` is the typed state model used by the planner and manager. Each
entry records:

- canonical address
- domain
- resource type
- resolved payload
- ordering dependencies
- refresh dependencies
- current status

This replaces the old untyped `resources/status` map.

## Capability Validation

Backends declare a `BackendManifest` composed of:

- `ProvisionerCapabilities`
- `OrchestratorCapabilities`
- zero or one `EvaluatorCapabilities`

Validation is semantic, not section-only. Phase 1 checks include:

- node types
- OS families
- total deployable node count
- ACL usage
- content types
- account features
- orchestration/workflow usage
- workflow predicate condition refs
- scoring/objective usage

## Runtime Target Lifecycle

Targets must provide an explicit manifest. The registry separates capability
inspection from instantiation, and `create()` uses the manifest returned by
`manifest()` as its single source of truth:

- `registry.manifest(name, **config)`
- `registry.create(name, **config)`

`RuntimeManager` drives lifecycle in this order:

1. compile
2. plan
3. validate provisioning apply
4. apply provisioning plan
5. start evaluator only when the evaluation plan has operations
6. start orchestrator only when the orchestration plan has operations
7. on failed runtime-service startup, roll back started services while keeping provisioning state
8. stop orchestrator -> stop evaluator -> delete provisioning resources

Objective `window` refs remain declarative scope/refresh inputs. They can force
objective refresh when referenced orchestration state changes, but they do not
create executor ordering edges across domains.

`RuntimeManager.apply()` requires the plan provenance to match the manager:

- same target name
- same manifest
- same base snapshot

This prevents applying a plan against a different runtime target or a stale
snapshot than the one it was reconciled against.

## Phase 1 Scope

Phase 1 intentionally stops at:

- compiler
- planner
- runtime manager
- registry
- honest in-memory stubs
- tests and docs

Real Docker/cloud/simulation backends come later on top of this contract.
