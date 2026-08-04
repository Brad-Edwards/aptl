---
id: DSL-001
title: "Formal Scenario Specification Language"
status: DEPRECATED
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-21T07:52:20.057307Z
updated_at: 2026-05-19T05:11:45.570071Z
---

# DSL-001: Formal Scenario Specification Language

## Statement

The platform shall define a formal scenario specification language (DSL) with a documented grammar, parser, and validation that goes beyond Pydantic structural checks to enforce semantic correctness of scenario definitions.

## Rationale

Current ad-hoc YAML schema has no grammar, no parser beyond Pydantic, and no semantic validation. Without a formal DSL, every other scenario improvement (parameterization, generation, batch runs, agent-driven execution) is built on a fragile foundation. CACAO v2.0, Attack Flow v3, VSDL, and Yamin & Katt's DSL demonstrate the pattern.

## Traceability

- IMPLEMENTS → GITHUB_ISSUE `239` (DSL-001: Formal Scenario Specification Language)
- DOCUMENTS → DOCUMENTATION `docs/sdl/` (SDL documentation suite (7 files: reference, parser, validation, precedents, limitations, testing))
- DOCUMENTS → ADR `docs/adrs/adr-014-scenario-description-language.md` (ADR-014: Scenario Description Language)
- VERIFIES → CODE_FILE `examples/aptl-lab-topology.sdl.yaml` (SDL specification of the real APTL lab topology (28 nodes, 4 networks))
