# Planner Graph Semantics

This directory holds the formal artifacts for dependency ordering and
reconciliation semantics.

## Scope

- typed dependency-edge semantics (`ordering` vs `refresh`)
- ordering dependency normalization
- cycle detection
- stable topological order for create/start
- reverse topological order for delete/teardown
- transitive refresh propagation
- reconciliation action semantics over desired resources vs snapshot state
- composition-ready identity invariants for future module/import expansion

## Implementation Mapping

- shared graph helpers: `src/aptl/core/semantics/planner.py`
- planner use sites:
  - `src/aptl/core/runtime/planner.py`
  - `src/aptl/core/runtime/manager.py`

## Tests

- `tests/test_semantics_planner.py`
- `tests/test_fm2_semantics.py`
- `tests/test_runtime_planner.py`
- `tests/test_runtime_manager.py`
