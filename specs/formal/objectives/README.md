# Objective Window Semantics

This directory holds the formal artifacts for objective window and reachability
semantics.

## Scope

- normalized story/script/event/workflow/workflow-step reference resolution
- consistency between `window.stories`, `window.scripts`, `window.events`,
  `window.workflows`, and `window.steps`
- reachability derivation from story -> script -> event chains
- refresh dependency derivation from workflow and workflow-step refs
- fail-closed behavior for invalid, dangling, or out-of-window references
- composition-ready invariants for later namespace/module expansion

## Implementation Mapping

- shared helpers: `src/aptl/core/semantics/objectives.py`
- semantic validation: `src/aptl/core/sdl/validator.py`
- compiled runtime diagnostics and dependency derivation:
  - `src/aptl/core/runtime/compiler.py`
  - `src/aptl/core/runtime/models.py`

## Tests

- `tests/test_semantics_objectives.py`
- `tests/test_fm2_semantics.py`
- `tests/test_sdl_validator.py`
- `tests/test_runtime_models.py`
