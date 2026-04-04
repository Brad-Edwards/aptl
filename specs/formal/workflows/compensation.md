# Workflow Compensation Semantics

## Scope

This artifact defines the backend-portable compensation semantics for SDL
workflows.

Compensation is:

- explicit in SDL
- compiled into workflow execution contracts
- observable in workflow execution state and history
- validated at the manager/control-plane boundary

It is not:

- implicit rollback
- backend-defined cleanup behavior
- general exception handling

## Model

Workflow-level compensation policy:

- `mode`: `automatic | disabled`
- `on`: subset of `failed | cancelled | timed_out`
- `failure_policy`: `fail_workflow | record_and_continue`
- `order`: fixed to `reverse_completion`

Step-level compensation target:

- `compensate-with: <workflow>`

Compensable step kinds:

- `objective`
- `call`

Non-compensable step kinds:

- `decision`
- `switch`
- `retry`
- `parallel`
- `join`
- `end`

## Registration

- a compensable step registers compensation only after it completes successfully
- registration is per workflow run
- registration order is derived from actual completion order, not source order

## Triggering

- compensation starts only when the workflow reaches a terminal status in the
  configured trigger set
- normal workflow success never triggers compensation
- `mode: disabled` suppresses compensation even when steps declare targets

## Ordering

- compensation executes in strict reverse completion order
- parallel branches share one global registration order based on actual
  completion time
- only successfully completed compensable steps participate

## Graph Rules

- every compensation target must resolve to a declared workflow
- the combined graph of normal `call` edges and `compensate-with` edges must
  remain acyclic
- a compensation workflow may not itself declare `compensate-with` steps

## Runtime Observation

Workflow execution state includes:

- `compensation_status`
- `compensation_started_at`
- `compensation_updated_at`
- `compensation_failures`

Workflow history may include:

- `compensation_registered`
- `compensation_started`
- `compensation_workflow_started`
- `compensation_workflow_completed`
- `compensation_workflow_failed`
- `compensation_completed`
- `compensation_failed`

Compensation status is separate from the primary terminal workflow status. A
workflow can be `cancelled` or `timed_out` while compensation is `running` or
`succeeded`.

## Implementation Mapping

- SDL authoring models: `src/aptl/core/sdl/orchestration.py`
- semantic validation: `src/aptl/core/sdl/validator.py`
- compiled contracts: `src/aptl/core/runtime/compiler.py`
- runtime state/history models: `src/aptl/core/runtime/models.py`
- manager validation: `src/aptl/core/runtime/manager.py`
- control-plane lifecycle handling: `src/aptl/core/runtime/control_plane.py`
