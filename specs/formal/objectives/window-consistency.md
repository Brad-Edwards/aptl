# Objective Window Consistency

## Window Reference Model

Objective windows can constrain visibility using:

- stories
- scripts
- events
- workflows
- workflow step references using `<workflow>.<step>`

## Consistency Rules

- `window.steps` must use `<workflow>.<step>` syntax
- `window.steps` require at least one referenced workflow
- each referenced workflow step must resolve to:
  - a defined workflow
  - a defined step within that workflow
- if `window.workflows` is present, every `window.steps` workflow name must be a member of that set

## Dependency Semantics

- `window.workflows` contributes orchestration workflow refresh dependencies
- `window.steps` contributes:
  - the stable step reference string
  - the owning workflow address for refresh propagation

## Fail-Closed Cases

- malformed step syntax
- undefined workflow names
- undefined step names
- step references outside the declared workflow window

## Implementation Mapping

- parsing helper: `src/aptl/core/semantics/objectives.py`
- validator checks: `src/aptl/core/sdl/validator.py`
- compiler diagnostics and refresh derivation: `src/aptl/core/runtime/compiler.py`
