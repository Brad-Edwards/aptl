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
- workflow predicate condition refs
- scoring/objective usage

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

## RTE-001 Guardrails

The scenario runtime engine must extend the SDL-native runtime described here.
It must not resurrect the retired `aptl scenario` imperative lifecycle from
ADR-009 or add a parallel objective/session state machine.

Objective evaluation belongs to the `evaluation` domain:

- SDL `objectives` remain declarative experiment semantics. Backend-specific
  probes such as Wazuh alert queries, command-output checks, and file-existence
  checks live in evaluator adapters or condition/scoring bindings, not in the
  objective schema itself.
- Evaluator state is reported through `RuntimeSnapshot.evaluation_results` and
  `Evaluator.results()`. If CLI/session views need a compatibility projection,
  they should derive it from evaluator results rather than making
  `ScenarioSession.completed_objectives` a second source of truth.
- Probe outcomes should update incrementally with stable resource addresses,
  structured payloads, and `Diagnostic` records. Backend exceptions, malformed
  probe results, and transient service failures should become runtime
  diagnostics and auditable result details, not uncaught manager failures.

Scheduling, pacing, and event progression belong to the `orchestration` domain:

- scripts, stories, workflows, `while`, `on-error`, and step outcomes are the
  orchestration surface; the evaluator observes and scores them but does not own
  workflow control flow.
- objective `depends_on` remains the objective ordering relation. Objective
  `window` refs constrain observation scope and refresh behavior; they do not
  create cross-domain executor ordering edges.

Durable run evidence should reuse the existing run archive surfaces:

- structured timeline/intervention records go to the run store as JSON/JSONL;
- human-readable summaries belong in `manifest.json` or documented archive
  notes;
- normal operator logs should use `aptl.utils.logging.get_logger()`.

The purple-team continuity carve-out from issue #252 is an orchestrator-side
intervention, not an active-response rewrite. The in-band whitelist remains
ADR-021's `aptl-firewall-drop` contract. The post-iteration audit that
inspects and removes blanket kali source-IP drops is modeled as an
orchestration lifecycle action with archive evidence and diagnostics — see
[ADR-024](../adrs/adr-024-orchestrator-side-purple-continuity-carve-out.md)
for the implementation contract.

Mode-gating: runtime behavior must not infer purple mode from filenames,
legacy fixtures, agents present, or CLI defaults. Today the continuity
carve-out runs unconditionally because every shipped APTL scenario is
purple by design — it does not read or guess `mode` from any source.
Once SDL adds an authoritative `mode` field (issue #263), the carve-out
gains a `scenario.mode == PURPLE` gate at its orchestration call site so
that `red` and `blue` runs are explicitly skipped. That migration is a
one-line change at the call site; deferring the schema work to #263 keeps
this layer ungated-by-design until the formal contract lands.

## Phase 1 Scope

Phase 1 intentionally stops at:

- compiler
- planner
- runtime manager
- registry
- honest in-memory stubs
- tests and docs

Real Docker/cloud/simulation backends come later on top of this contract.
