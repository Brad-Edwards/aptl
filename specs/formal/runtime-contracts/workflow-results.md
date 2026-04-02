# Workflow Result Contract

## Envelope

Each workflow result is a plain-data portable envelope with:

- `state_schema_version`
- `workflow_status`
- `run_id`
- `started_at`
- `updated_at`
- optional `terminal_reason`
- `steps`

`state_schema_version` is fixed to `workflow-step-state/v1` in this rollout.

## Step State

Each observable step result contains:

- `lifecycle`: `pending | running | completed`
- `outcome`: optional until completion, then required
- `attempts`: non-negative integer

## Semantic Constraints

- only observable step kinds may appear in `steps`
- all observable steps from the compiled workflow contract must appear in `steps`
- workflow-level status must be explicit and portable
- terminal workflow statuses require a `terminal_reason`
- non-completed steps may not report an outcome
- pending steps must report `0` attempts
- completed steps must report an outcome legal for their step kind
- fixed-attempt step kinds must report their fixed attempt count when completed

## History

Workflow observation is split into:

- the current execution-state envelope
- a separate ordered workflow history stream

History events are validated against the compiled workflow `execution_contract`
so the manager can reject impossible global causality, not just illegal
step-local states.

## Validation Boundary

Backends may hold richer internal state, but the manager only accepts the
portable envelope defined here. Validation is performed against the compiled
workflow `result_contract` and `execution_contract`, not against incidental
planner payload fields such as `control_steps`.

Python typed models may normalize valid payloads after validation, but they are
not the backend-facing contract.
