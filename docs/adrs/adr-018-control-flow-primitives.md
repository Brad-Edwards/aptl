# ADR-018: Control Flow Primitives in the SDL

## Status

superseded by ADR-019

This ADR is preserved as historical context for the exploratory `if` / `while`
workflow surface. The current SDL and runtime semantics are defined by
ADR-019 and the corresponding SDL reference docs.

## Date

2026-04-01

## Context

[ADR-016](adr-016-workflows-targetable-subobjects-and-enum-variables.md) introduced declarative workflows to the SDL with four step types: `objective`, `if`, `parallel`, and `end`. The [limitations document](../sdl/limitations.md) identified loops, error recovery, and richer conditional branching as the primary remaining control flow gaps, citing CACAO v2.0 workflow types as a precedent.

Real attack scenarios involve retry-with-variation loops (e.g., credential spraying with different wordlists), error recovery paths (e.g., falling back to a different exploit when the primary one fails), and branching decisions based on whether a prior step succeeded or failed. The existing `if` predicate could reference conditions, metrics, and objectives, but could not reference the outcome of a previously executed workflow step.

## Decision

Extend the SDL workflow surface with three coordinated additions.

### 1. `while` step type

A new `WorkflowStepType.WHILE` models loop/retry control flow. A `while` step requires:

- `when`: a `WorkflowPredicate` evaluated before each iteration
- `body`: the name of the step to execute in each iteration

Optional fields: `next` (step after the loop exits), `max-iterations` (positive integer or `${var}`, capping iteration count), `on-error` (recovery step), and `description`.

**DAG preservation:** The `while` step is modeled as a single node in the workflow DAG with forward edges to `body`, `next`, and `on-error`. There is no back-edge from the body to the `while` step. The `while` node itself carries iteration semantics; the underlying graph remains a proper DAG. This preserves the existing cycle detection and reachability analysis unchanged.

### 2. `on-error` recovery handlers

`objective`, `while`, and `parallel` steps gain an optional `on-error` field naming the step to transition to if the current step fails at runtime. The `on-error` reference:

- Must be a valid step name in the same workflow
- Must not reference the step itself
- Adds a forward edge in the workflow DAG, making recovery steps reachable

`if` and `end` steps do not support `on-error` because they have no execution semantics that can fail.

### 3. `step-outcomes` in workflow predicates

`WorkflowPredicate` gains a `step-outcomes` field: a list of step names whose success/failure outcome the predicate references. This allows `if` and `while` predicates to branch based on whether a prior objective step succeeded or failed, closing the "conditionals based on action outcomes" requirement.

Step outcome references are validated against the step names in the same workflow but do not produce external resource addresses in the compiler since they are internal workflow state.

## Consequences

### Positive

- Retry-with-variation and loop patterns are now directly expressible in the SDL.
- Error recovery paths are first-class graph edges, visible to inspection and validation tools.
- Outcome-based branching allows workflows to adapt based on prior step results without requiring external condition/metric infrastructure.
- The workflow DAG remains cycle-free; existing topological sort and reachability analysis are unaffected.

### Negative

- The workflow surface grows again, increasing validation and documentation surface area.
- `while` iteration semantics are carried by the node rather than the graph structure, which means static analysis tools cannot reason about loop termination from the graph alone.
- `max-iterations` is optional; unbounded loops are the author's responsibility.

### Risks

- Authors may expect `while` to model graph-level back-edges rather than per-node iteration. Documentation must make the single-node semantics clear.
- `on-error` adds a second control flow path out of action steps. Runtime implementations must ensure exactly one path is taken per step execution.
