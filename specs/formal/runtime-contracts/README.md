# Runtime Contract Semantics

This directory holds the formal artifacts for portable runtime result contracts.

## Scope

- typed workflow execution envelopes
- typed workflow step execution state
- typed evaluator result envelopes
- typed evaluator history streams
- manager-side validation of backend workflow results
- manager-side validation of backend evaluator results

## Implementation Mapping

- shared result constraints: `src/aptl/core/semantics/workflow.py`
- typed result models: `src/aptl/core/runtime/models.py`
- manager contract validation: `src/aptl/core/runtime/manager.py`
- backend example: `src/aptl/backends/stubs.py`

## Tests

- `tests/test_runtime_manager.py`
- `tests/test_runtime_models.py`
- `tests/test_runtime_contracts.py`
