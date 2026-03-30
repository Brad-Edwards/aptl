# ADR-015: Declarative Experiment Objectives in the SDL

## Status

accepted

## Date

2026-03-29

## Context

[ADR-014](adr-014-scenario-description-language.md) established the APTL SDL as a backend-agnostic specification language grounded in the Open Cyber Range (OCR) SDL and extended with additional sections adapted from other precedents.

During initial implementation, the branch preserved OCR's scoring pipeline (`conditions -> metrics -> evaluations -> TLOs -> goals`) in the SDL, but treated APTL-style objectives primarily as runtime concerns because the legacy implementation had mixed together:

- experiment meaning
- backend-specific validation probes
- scenario engine behavior

That cleanup removed legacy runtime coupling, but it left an architectural gap: the SDL could describe topology, orchestration, agents, and scoring criteria, yet it lacked a first-class way to declare who was trying to do what, against which targets, during which exercise window, and by what success semantics.

Research and precedent review pointed in the same direction:

- **OCR** keeps assessment semantics in the specification layer, not only in runtime.
- **CACAO** keeps agent/target/workflow intent in the playbook specification while leaving execution adapters external.
- **CybORG** places agent-facing configuration such as actions, initial knowledge, and reward-calculator choice in scenario definitions.

The design question was therefore not whether to restore the legacy APTL runtime `objectives` block, but whether the SDL itself should carry declarative experiment semantics.

## Decision

Add a first-class `objectives` section to the SDL for declarative experiment semantics.

Each objective may declare:

- exactly one actor: `agent` or `entity`
- optional `actions`
- optional `targets`
- required `success` criteria referencing declared `conditions`, `metrics`, `evaluations`, `tlos`, or `goals`
- optional `window` constraints over `stories`, `scripts`, and `events`
- optional `depends_on` links forming an acyclic ordering relation between objectives

This section is intentionally declarative. It expresses:

- who is acting
- what they are trying to affect
- when the objective matters
- how success should be interpreted

It does **not** encode backend-specific validation probes such as Wazuh queries, command execution, file checks, polling loops, or session orchestration. Those remain runtime concerns and continue to live outside the SDL.

### Relationship to ADR-014

This ADR refines ADR-014's SDL boundary by making declarative objectives part of the language itself while preserving ADR-014's backend-agnostic separation between specification and deployment/runtime mechanics.

## Consequences

### Positive

- The SDL now captures experiment meaning more completely, not just topology and scoring fragments.
- Agent definitions, orchestration, scoring, and objectives can be authored and reviewed together in one specification surface.
- The runtime boundary is cleaner: the SDL defines semantics, while runtime adapters define how those semantics are checked.
- Objective dependencies can be validated structurally as an acyclic ordering graph.

### Negative

- The SDL surface area grows, increasing documentation and test burden.
- The distinction between declarative objective semantics and runtime evaluation mechanics must remain explicit to avoid drift back into engine-coupled schema design.
- Real-world stress scenarios need to keep pace so the section is exercised beyond unit tests.

### Risks

- If future runtimes need richer control flow, the current objective model may need to evolve toward a more explicit workflow model.
- Authors may infer stronger execution semantics than currently implemented unless `depends_on`, `window`, and success rules are documented precisely.
- Divergence from OCR/CACAO details remains possible if future changes borrow terminology without preserving the underlying conceptual boundary.
