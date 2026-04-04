# Evaluator Result Contract

## Envelope

Each evaluator-observable address reports a plain-data portable result envelope
with:

- `state_schema_version`
- `resource_type`
- `run_id`
- `status`
- `observed_at`
- `updated_at`
- optional `passed`
- optional `score`
- optional `max_score`
- optional `detail`
- optional `evidence_refs`

`state_schema_version` is fixed to `evaluation-result-state/v1` in this rollout.

## Resource Contracts

Evaluator result semantics are compiled per observable address.

Current v1 contracts:

- `condition-binding` -> `passed`
- `metric` -> `score` and fixed `max_score`
- `evaluation` -> `passed`
- `tlo` -> `passed`
- `goal` -> `passed`
- `objective` -> `passed`

The manager validates raw backend payloads against the compiled
`result_contract` attached to each evaluation resource, not against incidental
payload conventions.

## Status Semantics

Portable statuses are:

- `pending`
- `running`
- `ready`
- `failed`

Constraints:

- `pending` and `running` may not report result values
- `ready` must report the value shape required by the compiled contract
- `failed` may report detail but not successful result values
- metrics may not report a score above compiled `max_score`

## History

Evaluator observation is split into:

- the current result envelope for each observable address
- a separate ordered history stream for that address

Current portable history events are:

- `evaluation_started`
- `evaluation_updated`
- `evaluation_ready`
- `evaluation_failed`

History timestamps must be monotonic. When history is present, it must begin
with `evaluation_started`. `ready` results must end with `evaluation_ready`, and
`failed` results must end with `evaluation_failed`.

## Validation Boundary

Backends may hold richer internal evaluator state, but the manager only accepts
the portable envelope and history defined here. Python typed models normalize
payloads after validation; they are not the backend-facing contract.
