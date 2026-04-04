# Coding Standards

## Semantic Engineering and Lightweight Formal Methods

APTL uses lightweight formal methods for semantic and stateful subsystems, not
for all code. The goal is to make behavior precise where ambiguity, graph
constraints, or execution-state semantics matter, while keeping ordinary
structural work lightweight.

The canonical decision framework is defined by
[ADR-020](../adrs/adr-020-lightweight-formal-methods-policy.md). This document
is the contributor-facing source of truth for how to apply that policy in day
to day implementation and review.

## Semantic Layers

When planning or reviewing a change, first identify which semantic layer it
touches.

### 1. Syntax / Parsing

Examples:

- YAML parsing
- key normalization
- shorthand expansion
- schema and field-level validation

This layer is usually `FM0`.

### 2. Static Semantics

Examples:

- cross-reference resolution
- ambiguity checks
- uniqueness rules
- dependency cycles
- fail-closed validation

This layer is usually `FM1`.

### 3. Dynamic Semantics

Examples:

- workflow branching, retry, join, and re-entry behavior
- visibility of prior step state
- planner reachability and dependency propagation

This layer is usually `FM2` or `FM3`.

### 4. Backend Contract Semantics

Examples:

- typed runtime IR
- result/status payload contracts
- portability guarantees across backends

Backend contracts at this layer must be language-neutral unless there is an
explicit protocol decision otherwise.

This layer is usually `FM2` or `FM3`.

## Classification Levels

### FM0 Structural

Use for shape/parsing/schema/local validation only.

Required artifacts:

- ordinary unit tests

Do not add TLA+ or Alloy for FM0 work.

**Repo example:** parser key normalization in `aptl.core.sdl.parser`, where
`start-time` becomes `start_time` but user-defined names remain concrete.

### FM1 Static Semantic

Use for cross-references, uniqueness, ambiguity, acyclicity, and fail-closed
resolution.

Required artifacts:

- invariant list in the plan or docs
- unit tests for the semantic rule

Recommended when cheap and useful:

- property-based tests

**Repo example:** relationship and objective target ambiguity, where a bare ref
such as `web` must fail closed when it could refer to multiple named elements.

### FM2 Semantic Graph / Constraint

Use for reachability, visibility, dependency propagation, planner ordering, and
portability rules.

Required artifacts:

- all FM1 artifacts
- typed IR/contract coverage for the affected semantic surface
- targeted property-based or differential tests when they improve confidence

**Repo example:** objective window consistency or planner dependency
propagation, where multiple references must remain internally consistent across
validation and compiled/runtime forms.

Current FM2 examples in APTL now include:

- normalized objective-window references that stay aligned across validator and
  compiler
- typed planner dependency semantics that distinguish `ordering` from `refresh`
  instead of inferring meaning from local algorithm structure

### FM3 Stateful / Control Semantics

Use for state machines, branching, retries, joins, re-entry, lifecycle
semantics, and result contracts.

Required artifacts:

- all FM2 artifacts
- explicit abstract state-machine model

TLA+ or Alloy is recommended only when the change introduces or materially
alters branching, re-entry, concurrency barriers, or cross-layer portability
guarantees.

**Repo example:** workflow branching/join/retry semantics, including which
transitions are legal, what state is visible before predicates, and what
portable outcomes different step kinds may emit.

## Decision Matrix

| Level | Typical problem | Required artifacts | Typical tools |
|------|------------------|--------------------|---------------|
| `FM0` | Structural shape only | Unit tests | Parser/model tests |
| `FM1` | Static semantic rule | Invariants + unit tests | Validator tests, table-driven tests |
| `FM2` | Graph/constraint semantics | FM1 + typed IR/contract coverage + targeted property/differential tests | Validator/compiler/planner tests |
| `FM3` | Stateful/control semantics | FM2 + abstract state-machine model | Typed runtime models, semantic tests, optional TLA+/Alloy |

## Use and Do Not Use

Use lightweight formal methods when a change introduces or modifies:

- branching or retries
- joins, convergence, or re-entry semantics
- “must be knowable on all paths” visibility rules
- cross-reference ambiguity or fail-closed resolution
- dependency graphs or propagation rules
- portability or result-contract guarantees between layers

Do not escalate into formal methods by default for:

- docs-only edits
- formatting-only changes
- trivial refactors with unchanged semantics
- isolated field additions with no new invariants
- simple parser normalization or aliasing
- straightforward CRUD/config plumbing

## Minimum Artifact Expectations

### FM0

- Unit tests only

### FM1

- Invariant list in the plan, ADR, or doc update
- Unit tests that pin valid and invalid cases

### FM2

- FM1 artifacts
- Typed IR/contract assertions covering the same rule after validation
- Property-based or differential tests when they materially improve coverage

### FM3

- FM2 artifacts
- Short abstract state-machine model describing states, transitions,
  invariants, and observation rules
- Optional TLA+/Alloy only when the semantic surface is risky enough to justify
  it

## Implementer Checklist

For any semantic or stateful change:

1. Classify the change as `FM0`, `FM1`, `FM2`, or `FM3`.
2. State the invariants or properties being added or changed.
3. Choose the minimum required artifacts for that level.
4. Decide whether a formal model is warranted or whether tests and typed models
   are sufficient.
5. Identify affected docs, tests, and contracts.
6. Keep validator, compiler, planner, and runtime language aligned when they
   describe the same behavior.
7. For composition-adjacent work, preserve canonical identity semantics so
   future namespace/module expansion can layer on without redefining FM2 rules.

For `FM2` and `FM3` changes, plans and reviews must explicitly name the
invariants and the required artifacts.

## Storage Conventions

Contributor-facing policy belongs in docs.

Optional formal artifacts belong under:

`specs/formal/<domain>/`

Machine-readable external contracts belong under:

`schemas/`

Each formal artifact should include a short README that explains:

- scope
- invariants or properties under study
- relationship to implementation and tests

## Review Expectations

Reviewers should ask:

- What semantic layer changed?
- Was the change classified at the right level?
- Are the invariants explicit?
- Are the chosen artifacts proportionate?
- Do docs, tests, and contracts tell the same story?

The goal is precision, not ceremony. Use the smallest adequate formalization
that makes the semantic behavior clear and testable.

## Near-Term Rollout

This policy establishes a path, not a requirement to formalize everything now.

The first follow-on candidate domains are:

1. workflow control semantics
2. objective window and reachability semantics
3. planner dependency/order semantics
4. runtime/backend result contract typing
