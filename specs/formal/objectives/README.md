# Objective Window Semantics

This directory holds the formal artifacts for objective window and reachability semantics.

## Scope

- `<workflow>.<step>` reference syntax and resolution
- consistency between `window.workflows` and `window.steps`
- refresh dependency derivation from window references
- fail-closed behavior for invalid or out-of-window references

## Implementation Mapping

- shared helpers: `src/aptl/core/semantics/objectives.py`
- semantic validation: `src/aptl/core/sdl/validator.py`
- compiled runtime diagnostics and dependency derivation:
  - `src/aptl/core/runtime/compiler.py`
  - `src/aptl/core/runtime/models.py`

## Tests

- `tests/test_sdl_validator.py`
- `tests/test_runtime_models.py`
