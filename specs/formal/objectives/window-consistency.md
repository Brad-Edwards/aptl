# Objective Window Consistency

## Window Reference Model

Objective windows can constrain visibility using normalized references to:

- stories
- scripts
- events
- workflows
- workflow steps using `<workflow>.<step>`

All objective-window references are resolved into a single normalized internal
shape before compiler/planner semantics run. Each resolved reference carries:

- raw author-facing text
- canonical name
- reference kind
- dependency role set
- optional workflow and step identity
- a namespace-extensible path slot reserved for future module/import work

## Consistency Rules

- `window.steps` must use `<workflow>.<step>` syntax
- `window.steps` require at least one referenced workflow
- each workflow ref must resolve to a declared workflow
- each workflow step ref must resolve to:
  - a declared workflow
  - a declared step within that workflow
- if `window.workflows` is present, every `window.steps` workflow name must be
  a member of that set
- if `window.stories` is present, every explicit `window.scripts` entry must be
  included by at least one referenced story
- if explicit or reachable scripts are known, every `window.events` entry must
  be included by at least one referenced script

## Reachability and Refresh Semantics

- referenced stories derive reachable scripts
- explicit scripts override story-derived reachability for event membership
  checks
- explicit or reachable scripts derive reachable events
- `window.workflows` contributes orchestration workflow refresh dependencies
- `window.steps` contributes:
  - the stable step reference string
  - the owning workflow address for refresh propagation
- objective refresh dependencies are therefore derived from one shared
  objective-window analysis rather than separate validator/compiler logic

## Fail-Closed Cases

- malformed workflow-step syntax
- undefined story/script/event/workflow names
- undefined step names
- script refs outside the declared story window
- event refs outside the explicit/reachable script window
- step refs outside the declared workflow window

## Composition-Ready Invariants

- normalized references are independent of source-file layout
- future module/import expansion must occur before this analysis runs
- namespacing may extend the reference identity, but must not change:
  - reference kinds
  - dependency role semantics
  - workflow-step ownership semantics

## Implementation Mapping

- shared semantic source of truth: `src/aptl/core/semantics/objectives.py`
- validator checks: `src/aptl/core/sdl/validator.py`
- compiled runtime references and refresh derivation:
  - `src/aptl/core/runtime/compiler.py`
  - `src/aptl/core/runtime/models.py`
- differential and property tests:
  - `tests/test_semantics_objectives.py`
  - `tests/test_fm2_semantics.py`
