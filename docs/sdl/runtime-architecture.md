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
- orchestration and scoring/objective sections -> resolved runtime programs and graph nodes

The output is a `RuntimeModel` with canonical addresses for every runtime-owned
object.

Bound condition refs fail closed. An unqualified condition reference must
resolve to exactly one bound runtime instance; zero matches and multiple matches
are both compile-time diagnostics. Event inject refs resolve directly to
top-level inject resources and fail if the named inject does not exist.
Bound feature dependencies also fail closed: if a node-scoped feature binding
declares a dependency on another feature that is not bound on the same node,
the compiler emits a diagnostic instead of silently dropping that dependency.

Compiled workflows are no longer just flattened successor maps. `WorkflowRuntime`
now preserves:

- `start_step`
- per-step structured semantics (`objective`, `decision`, `retry`, `parallel`, `join`, `end`)
- explicit control edges
- external predicate dependencies
- prior-step state dependencies
- declared workflow feature usage
- a versioned workflow-state schema for backend results

### 2. Plan

`plan(runtime_model, manifest, snapshot, target_name=None)` is also pure.

It validates semantic backend requirements and reconciles desired runtime
objects against the current `RuntimeSnapshot`.

`ExecutionPlan` is composite:

- `ProvisioningPlan` for deployable resources and bindings
- `OrchestrationPlan` for events, scripts, stories, workflows, and inject state
- `EvaluationPlan` for condition bindings, scoring graph nodes, and objectives

Each plan is provenance-bound to:

- an optional target name
- the backend manifest used for validation
- the base snapshot it was reconciled against

Direct planner output is unbound by default. Only `RuntimeManager.plan()` or an
explicit `target_name=` bind a plan to a concrete runtime target for apply.

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
Ordering graphs must remain acyclic within each domain; the planner emits error
diagnostics and invalidates the plan if a cycle survives into runtime planning.

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
- fine-grained workflow feature usage (`decision`, `retry`, `parallel` barriers, failure transitions)
- workflow predicate condition refs
- workflow predicate prior-step state refs and state-predicate subfeatures (`outcome-matching`, `attempt-counts`)
- scoring/objective usage

`OrchestratorCapabilities` now expose both coarse workflow support and fine-grained workflow semantics:

- `supports_workflows`
- `supports_condition_refs`
- `supported_workflow_features`
- `supported_workflow_state_predicates`

Variable-backed capability fields are handled soundly:

- capability-relevant variable refs must be declared, even when SDL semantic
  cross-reference validation was skipped earlier
- if a referenced variable has finite `allowed_values`, the planner first
  revalidates that domain against the SDL field being parameterized
  (`nodes.os`, `infrastructure.count`) before any backend capability checks run
- only field-valid finite domains are checked against backend capabilities
- declared variables without a finite field-valid pre-instantiation domain emit
  warning diagnostics and defer exact validation until instantiation rather
  than guessing from defaults

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
5. start evaluator only when the evaluation plan has actionable operations
6. start orchestrator only when the orchestration plan has actionable operations
7. on failed runtime-service startup, roll back started services while keeping provisioning state
8. stop orchestrator -> stop evaluator -> delete provisioning resources

The orchestration runtime contract now includes a portable workflow-results surface.
Backends report workflow step lifecycle/outcome state using the compiled workflow
state schema rather than backend-native payloads. Compiled workflow predicates
are fully typed runtime data; orchestrators should not rely on raw SDL `spec`
to execute workflow semantics.

Objective `window` refs remain declarative scope/refresh inputs. They can force
objective refresh when referenced orchestration state changes, but they do not
create executor ordering edges across domains.

`RuntimeManager.apply()` requires the plan provenance to match the manager:

- plan must be target-bound
- same target name
- same manifest
- same base snapshot

This prevents applying a plan against a different runtime target or a stale
snapshot than the one it was reconciled against.

`RuntimeTarget` is self-validating at construction time:

- manifest presence and component shape must match
- required protocol methods must exist
- those methods must be invokable with the runtime's actual call shapes, not
  just be present by name

`RuntimeManager` also hardens the execution boundary at call time. Backend
exceptions and invalid lifecycle return payloads are converted into structured
runtime diagnostics instead of surfacing as unhandled crashes.

## Phase 1 Scope

Phase 1 intentionally stops at:

- compiler
- planner
- runtime manager
- registry
- honest in-memory stubs
- tests and docs

Real Docker/cloud/simulation backends come later on top of this contract.
