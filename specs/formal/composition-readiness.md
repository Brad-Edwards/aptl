# Composition Readiness

This note records the semantic invariants that later module/import and
namespace work must preserve.

## Phase Boundary

This FM2 phase does **not** implement:

- module/import syntax
- reusable workflow subflows
- source-file-level namespace syntax

It does lock the semantic preconditions those features must respect.

## Required Invariants

- module/import expansion must occur before full semantic validation and
  compile
- objective/window reference analysis must run on expanded canonical identities,
  not on author-facing module-local names
- planner dependency semantics must operate on resolved canonical resource
  identities, not on source-file boundaries
- future namespacing may extend canonical identity shape, but must not change:
  - objective-window reference kinds
  - dependency role meanings
  - planner `ordering` vs `refresh` edge semantics

## Current Implementation Hooks

- objective/window references already carry a namespace-extensible path slot in
  `src/aptl/core/semantics/objectives.py`
- planner identity handling is already defined in terms of canonical compiled
  addresses in `src/aptl/core/semantics/planner.py`

These hooks are intended to let module/import work land later without
redefining FM2 semantics.
