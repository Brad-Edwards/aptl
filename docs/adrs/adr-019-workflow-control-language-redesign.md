# ADR-019: Workflow Control-Language Redesign

## Status

accepted

## Date

2026-04-01

## Context

[ADR-016](adr-016-workflows-targetable-subobjects-and-enum-variables.md) introduced
first-class SDL workflows as a declarative objective-composition layer.
[ADR-018](adr-018-control-flow-primitives.md) then attempted to close key control
gaps by adding `while`, `on-error`, and `step-outcomes`.

That exploratory design exposed a deeper problem: the SDL had gained more control
surface without gaining a precise execution-state model. `while` relied on
node-level prose rather than a portable control semantic, `on-error` created
extra edges without a stronger failure contract, and `step-outcomes` validated
existence rather than whether a referenced result was actually knowable at that
point in control flow.

For autonomous, reproducible red/blue/purple experiments, workflows need to be a
serious backend-agnostic control language with:

- explicit step semantics
- explicit success/failure/retry behavior
- explicit concurrency barriers
- explicit workflow-visible state
- honest runtime capability declarations

## Decision

Redesign SDL workflows around explicit portable control semantics instead of
loosely annotated graph edges.

### 1. Replace the exploratory workflow surface

The old exploratory additions are removed from the SDL core:

- remove `while`
- remove `on-error`
- remove `step-outcomes`
- remove `if` as the canonical branching step name

`ADR-018` is superseded by this redesign.

### 2. Standardize v1 workflow step kinds

The SDL workflow language now uses six step kinds:

- `objective`
- `decision`
- `retry`
- `parallel`
- `join`
- `end`

Their semantics are:

- `objective`: run a declared objective, continue via required `on-success`, and
  optionally route failures via `on-failure`
- `decision`: branch on a declarative predicate via `then` / `else`
- `retry`: re-run a declared objective until success or `max-attempts` is
  exhausted; continue via required `on-success` and optionally route exhaustion
  via `on-exhausted`
- `parallel`: launch two or more branches concurrently and require all explicit
  branch paths to converge on a declared `join`; the join is not a normal
  direct successor edge from the parallel step
- `join`: explicit barrier that resumes linear control via `next` only after
  the owning `parallel` step has observed every branch converge
- `end`: terminal step

Cycles remain illegal in v1. Nested block syntax is deferred; the shipped v1
surface only includes flat named-step forms whose semantics stay crisp in that
model.

### 3. Define workflow-visible execution state

Workflow predicates may observe two categories of state:

- external evaluation state (`conditions`, `metrics`, `evaluations`, `tlos`,
  `goals`, `objectives`)
- prior workflow step state via `steps`

Step-state predicates name a prior executable step plus expected portable
outcomes (`succeeded`, `failed`, `exhausted`) and an optional minimum attempt
count.

Workflow-visible state is an immutable execution history. In v1, predicates may
observe step outcomes and attempt counts, but not backend-native failure classes.
Predicates may only reference prior executable steps whose state is guaranteed to
be known before the predicate executes. After a join, downstream predicates may
inspect executable branch steps from that fanout when those steps are guaranteed
on every path within their own branch before the join.

### 4. Keep the SDL core backend-agnostic

The redesigned workflow language stays inside the SDL's backend-agnostic
boundary. It orchestrates declared objectives and portable control semantics; it
does not embed backend-native commands or probes.

Backends remain responsible for realizing objective execution and reporting
portable workflow results through the runtime contract.

### 5. Refine runtime/compiler/capability contracts

Compiled workflows now preserve structured control semantics directly instead of
only flattened successor maps. Runtime workflow predicates are compiled into
typed execution data rather than requiring backend re-reads of raw SDL `spec`.
Runtime workflow results use a versioned portable workflow-state schema.

Backend capability declarations remain explicit and now include fine-grained
workflow support, including typed workflow feature and state-predicate enums:

- workflow feature support (`decision`, `parallel` barriers, `retry`, failure transitions)
- support for condition-backed predicates
- support for predicates over prior step state (`outcome-matching`, `attempt-counts`)

The planner fails closed when a scenario requires workflow semantics the target
does not declare.

## Consequences

### Positive

- Workflow control semantics are portable enough to support reproducible
  experiments across environments.
- Retries, failure handling, and concurrency barriers now have explicit SDL
  meaning instead of being inferred from graph shape plus prose.
- Workflow-visible state is part of the language contract, which enables
  stronger static validation.
- Runtime capability validation is more honest because it checks semantic
  workflow features rather than only a coarse `supports_workflows` flag.

### Negative

- This is a breaking change for the exploratory control-flow syntax introduced
  by ADR-018.
- Authors must now be more explicit, especially around success/failure
  transitions and parallel joins.
- The runtime/compiler surface grows because workflows now carry a richer state
  and capability contract.

### Risks

- The flat named-step model still intentionally defers reusable subflows and
  nested block syntax, so pressure for additional workflow structure is likely
  to return later.
- Parallel control remains the most semantics-heavy part of v1; docs and tests
  must keep the "every explicit branch path converges on one join" rule clear.
- If future backend-specific extensions are added carelessly, they could weaken
  the core portability guarantees established here.
