# Workflow State Machine

## State Variables

- `current`: the active control location or locations
- `steps[step].lifecycle`: `pending | running | completed`
- `steps[step].outcome`: `none | succeeded | failed | exhausted`
- `steps[step].attempts`: non-negative integer
- `workflow.status`: backend-local execution status outside the portable step-state envelope

The portable workflow result contract exposes only workflow-visible step state
through a wire-safe plain-data envelope. Language-native runtime models may be
derived from that envelope after validation.

## Step Kinds

- `objective`
  - observable outcomes: `succeeded`, `failed`
  - attempts: exactly `1` once running or completed
- `retry`
  - observable outcomes: `succeeded`, `exhausted`
  - attempts: total number of tries performed
- `parallel`
  - observable outcomes: `succeeded`, `failed`
  - attempts: exactly `1` once running or completed
- `decision`
  - not step-state observable
- `join`
  - not step-state observable
- `end`
  - not step-state observable

## Transition Rules

- `objective`
  - `pending -> running -> completed`
  - `completed.outcome in {succeeded, failed}`
- `retry`
  - `pending -> running -> completed`
  - `completed.outcome in {succeeded, exhausted}`
- `parallel`
  - `pending -> running -> completed`
  - `completed.outcome = succeeded` iff every explicit branch converged on the declared join and control passed the barrier
  - `completed.outcome = failed` iff the runtime took `on-failure` or the parallel step terminated without successful convergence
- `decision`
  - chooses exactly one of `then` or `else`
- `join`
  - reconverges an owning parallel's explicit branches
- `end`
  - terminates control flow

## Join Semantics

- each `join` has exactly one owning `parallel`
- the owning parallel defines the legal branch roots
- only nodes in the owning parallel's branch closure may directly enter the join
- every explicit branch path must converge on the join

## Predicate Visibility

- step-state predicates may target only observable step kinds
- a predicate may reference only step state guaranteed to be known on every path before that predicate executes
- after a `join`, the visible set includes:
  - the owning `parallel`
  - branch-local step state guaranteed on every path within each branch before the join

## Implementation Mapping

- semantic contract definitions: `src/aptl/core/semantics/workflow.py`
- validation and visibility checks: `src/aptl/core/sdl/validator.py`
- compiled step contracts: `src/aptl/core/runtime/compiler.py`
- typed runtime envelopes and result validation:
  - `src/aptl/core/runtime/models.py`
  - `src/aptl/core/runtime/manager.py`
