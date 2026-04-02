# Workflow Semantics

This directory holds the repo-native formal artifacts for SDL workflow control semantics.

## Scope

- workflow step kinds and their observable state contracts
- legal transitions for `objective`, `retry`, `parallel`, `decision`, `join`, and `end`
- join ownership and legal join entry
- step-state visibility before predicate evaluation
- portable workflow result envelopes

## Invariants

- every `join` has exactly one owning `parallel`
- only the owning parallel's branch closure may enter its `join`
- every explicit branch path converges on the declared `join`
- only observable step kinds may be referenced in step-state predicates
- step-state predicates may only ask for outcomes legal for the referenced step kind
- post-join visibility contains only step state guaranteed on every path to the join

## Implementation Mapping

- shared rules: `src/aptl/core/semantics/workflow.py`
- validator enforcement: `src/aptl/core/sdl/validator.py`
- compiled contracts: `src/aptl/core/runtime/compiler.py`
- typed runtime results and contract checks:
  - `src/aptl/core/runtime/models.py`
  - `src/aptl/core/runtime/manager.py`
- smoke/regression coverage:
  - `tests/test_sdl_validator.py`
  - `tests/test_runtime_models.py`
  - `tests/test_runtime_manager.py`

## Notes

This first wave uses Markdown as the abstract model format. TLA+ or Alloy can be added later for especially risky changes without changing the code-facing contract described here.
