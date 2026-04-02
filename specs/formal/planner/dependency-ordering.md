# Dependency Ordering

## Graph Model

Planner semantics operate on canonical compiled resource identities, not on
source-file locality or authoring layout.

Resources expose two typed dependency classes:

- `ordering`
- `refresh`

`ordering` edges define create/start and delete/teardown semantics.
`refresh` edges define recomputation/update propagation when upstream state
changes.

## Required Properties

- dependency graphs are normalized to known nodes only
- ordering dependencies are evaluated per domain for cycle detection and stable
  topological order
- create/start order is the ordering topological order
- delete/teardown order is the reverse of ordering topological order
- refresh propagation is transitive over the refresh graph
- refresh propagation does not create cross-domain startup ordering
- ordering cycles are reported fail-closed and invalidate the plan

## Reconciliation Semantics

Given desired resources and a prior snapshot:

- missing resources become `create`
- changed resources become `update`
- removed resources become `delete`
- unchanged resources remain `unchanged` unless refresh propagation promotes
  them to `update`

Refresh promotion uses the shared refresh graph closure rather than local
planner heuristics.

## Provenance and Applicability

The planner produces a plan bound to:

- the validated backend manifest
- the target name when known
- the base snapshot used for reconciliation

Applicability checks compare those provenance anchors before apply. This keeps
semantic planning and runtime execution aligned even when snapshots or targets
change.

## Composition-Ready Invariants

- dependency semantics operate on resolved canonical identities
- later module/import expansion may change how identities are produced, but not
  how typed dependency edges are interpreted
- planner ordering and refresh semantics must remain independent of source-file
  boundaries

## Implementation Mapping

- shared semantic source of truth: `src/aptl/core/semantics/planner.py`
- planner use sites:
  - `src/aptl/core/runtime/planner.py`
  - `src/aptl/core/runtime/manager.py`
- property and agreement tests:
  - `tests/test_semantics_planner.py`
  - `tests/test_runtime_planner.py`
  - `tests/test_fm2_semantics.py`
