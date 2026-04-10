# ADR-020: Lightweight Formal Methods Policy for Semantic Systems

## Status

accepted

## Date

2026-04-01

## Context

APTL's SDL and runtime layers now contain multiple semantic surfaces that are
more than ordinary data validation. The parser normalizes YAML into typed SDL
models; semantic validation checks cross-references, ambiguity, reachability,
and fail-closed constraints; the runtime compiler and planner preserve
execution meaning across backends. Workflow control semantics are the clearest
current example, but the same class of problem also appears in objective
windows, planner dependency ordering, and runtime/backend result contracts.

The repository already uses strong tests and property-based fuzzing for parser
robustness, but it does not yet define when a change should stop at ordinary
unit tests versus when it should add explicit invariants, typed semantic
models, property tests, or a small abstract state-machine specification.

Without a repo-wide policy, contributors and automation are likely to make
inconsistent decisions: some changes will under-specify subtle semantic
behavior, while others will over-rotate into heavyweight formalization for work
that is only structural.

Literature and implementation precedent point in the same direction:

- cyber-range SDL surveys consistently identify formal semantics and behavioral
  fidelity as the gap between "valid YAML" and "correct executable scenario"
- academic systems such as VSDL and CRACK push semantic meaning into solver or
  logic layers rather than leaving it implicit in configuration text
- mature workflow systems such as AWS Step Functions, Argo Workflows, and
  SCXML publish explicit control-flow semantics for branching, retries,
  parallelism, and completion rather than treating them as parser-local rules
- mature multi-runtime systems such as Kubernetes and Temporal use
  language-neutral runtime contracts and typed internal adapters, rather than
  host-language objects as the execution boundary

APTL is intentionally taking a lighter-weight path than solver-backed systems,
but it should still follow the same architectural pattern: approachable surface
syntax, explicit semantic invariants, typed intermediate contracts, and
portable runtime boundaries.

## Decision

Adopt a repo-wide lightweight formal-methods policy for semantic and stateful
subsystems, using SDL/runtime semantics as the first deep pilot.

### Scope

The primary formalization target is the semantic pipeline:

`YAML -> SDL models -> semantic validator -> runtime compiler -> planner/runtime contract`

This policy applies across the repository wherever a change introduces or
modifies semantic/stateful behavior. It does not mean all code is treated as a
formal-methods surface.

### Out of Scope by Default

The following do not require formal methods unless they also introduce new
semantic invariants:

- raw YAML syntax and parsing mechanics
- ordinary schema validation
- formatting and editorial documentation changes
- trivial refactors with unchanged semantics
- isolated field additions with no new invariants
- simple parser normalization or aliasing
- straightforward CRUD/config plumbing

### Approved Techniques

Use the smallest adequate technique, in increasing cost:

1. explicit invariants
2. typed intermediate/result models
3. table-driven semantic tests
4. property-based tests
5. abstract state-machine specifications
6. TLA+ or Alloy for especially risky or novel FM3 surfaces

Formal methods are chosen by classification level, not by subsystem prestige or
novelty.

This keeps the repository aligned with mature DSL/runtime practice:

- simple syntax and schema work stays lightweight
- graph and state-machine semantics become explicit and testable
- portable runtime contracts stay language-neutral at the boundary
- solver-backed methods remain selective rather than mandatory

### Classification Levels

#### FM0 Structural

Shape/parsing/schema/local validation only.

Required artifacts:

- ordinary unit tests

Not appropriate for TLA+ or Alloy.

#### FM1 Static Semantic

Cross-references, uniqueness, ambiguity, acyclicity, and fail-closed
resolution.

Required artifacts:

- invariant list in the plan or docs
- unit tests covering the invariant behavior

Recommended when cheap and useful:

- property-based tests

#### FM2 Semantic Graph / Constraint

Reachability, visibility, dependency propagation, planner ordering, and
portability rules.

Required artifacts:

- all FM1 artifacts
- typed IR or contract coverage for the affected semantic surface
- targeted property-based or differential tests where they improve confidence

#### FM3 Stateful / Control Semantics

State machines, branching, retries, joins, re-entry, lifecycle semantics, and
result contracts.

Required artifacts:

- all FM2 artifacts
- explicit abstract state-machine model

TLA+ or Alloy is recommended only when a change introduces or materially alters
branching, re-entry, concurrency barriers, or cross-layer portability
guarantees.

### Rollout Path

This ADR establishes policy and conventions only. It does not commit the
repository to immediately formalizing every candidate domain.

The first follow-on candidate domains, in order, are:

1. workflow control semantics
2. objective window and reachability semantics
3. planner dependency/order semantics
4. runtime/backend result contract typing

The rollout order mirrors the places where both the literature and existing
systems show the highest semantic risk:

- workflow control first, because branching, retries, joins, and re-entry are
  classic state-machine problems
- objective windows and planner ordering next, because they are graph and
  reachability surfaces
- backend result contracts after that, because mature systems require portable
  execution-state boundaries once multiple runtimes or languages are in play

### Storage Conventions

Contributor-facing policy lives in docs.

Optional formal artifacts live under:

`specs/formal/<domain>/`

Each such artifact must include a short README explaining:

- scope
- invariants or properties under study
- relationship to implementation and tests

## Consequences

### Positive

- The repository gains a shared language for deciding when semantic changes
  need more than ordinary unit tests.
- SDL/runtime work can be formalized incrementally without forcing heavyweight
  methods onto every change.
- Contributor guidance, ADRs, and automation can stay aligned on one policy.
- Workflows can serve as the first deep example without locking the policy to
  workflow-only concerns.
- The policy matches the shape of proven systems: state-machine rigor where
  control flow matters, portable contracts where runtime boundaries matter, and
  ordinary testing where code is only structural.

### Negative

- Contributors must now classify semantic/stateful changes and justify the
  chosen level of rigor.
- Some documentation and planning overhead is added for FM1+ changes.
- Reviewers must spend more time validating that the selected artifacts are
  proportionate and complete.

### Risks

- If the levels are applied mechanically, contributors may cargo-cult artifacts
  that do not improve understanding.
- If the policy is not reflected consistently in docs, contributor guidance,
  and automation, the repository will regress into inconsistent usage.
- The policy deliberately stops short of mandatory solver-backed verification,
  so subtle FM3 bugs can still exist when invariants and tests are weak.
