# ADR-014: Scenario Description Language (SDL)

**Status:** Accepted
**Date:** 2026-03-29
**Deciders:** Brad Edwards

## Context

APTL's scenario format was an ad-hoc YAML schema validated only by Pydantic structural checks. The DSL-001 requirement called for a formal specification language with a documented grammar, parser, and semantic validation. Research across 12 cybersecurity SDLs, 10 adjacent DSLs, 6 security standards, and 6 agent evaluation frameworks (documented in `Kepler/research/dsl/`) identified the Open Cyber Range (OCR) SDL as the closest existing precedent.

The OCR SDL is a YAML-based language with 14 sections (nodes, infrastructure, features, conditions, vulnerabilities, metrics/evaluations/TLOs/goals, entities, injects/events/scripts/stories) parsed by a Rust library. It separates logical topology from physical deployment and includes a full scoring pipeline and exercise orchestration model.

However, the OCR SDL lacks: data/content modeling, user accounts, network access controls, OS classification, asset values, service exposure, platform-targeted commands, relationships between services (authentication, trust, federation), agent specifications, and parameterization.

## Decision

Use the OCR SDL as the starting surface for `aptl.core.sdl`, preserve coverage across the OCR-derived sections, extend that base with 7 new sections adapted from existing systems (not invented), and decouple the language from any specific deployment backend.

### Architecture

The SDL is a **specification language**, not a deployment tool. It describes *what a scenario is*. A separate provider binding layer (future work) translates SDL specifications into concrete infrastructure.

### Sections (21 total)

14 OCR-derived base sections + 7 new:
- `content` (from CyRIS) — data placed into systems
- `accounts` (from CyRIS) — user accounts within nodes
- `relationships` (from STIX SRO) — typed edges between elements
- `agents` (from CybORG) — autonomous participants
- `objectives` (from OCR scoring + CACAO workflow context) — declarative experiment semantics
- `workflows` (from CACAO workflow patterns) — branching and parallel objective composition
- `variables` (from CACAO) — parameterization

### Identity Model

Identity is not a separate section. It emerges from the combination of:
- **Accounts** — who exists where (username, groups, SPN, password strength)
- **Features** — what provides authentication (AD, LDAP, RADIUS services)
- **Relationships** — how services connect (`authenticates_with`, `trusts`, `federates_with`)

This is simpler and more composable than a dedicated identity layer.

### Validation

Two-phase validation:
1. **Structural** (Pydantic) — types, ranges, required fields, intra-model constraints
2. **Semantic** (SemanticValidator) — 22 named passes checking cross-references, dependency cycles, IP/CIDR consistency, typed VM/network references, OCR count constraints, workflow graph integrity, and SDL domain rules

The validator collects all errors rather than failing on the first.

### Parser

The parser handles:
- Case-insensitive field keys (preserving user-defined names)
- Shorthand expansion (source strings, infrastructure counts, role strings, min-score integers, feature lists)
- SDL-only parsing with clean rejection of removed legacy `metadata` scenarios
- Clean error messages for all failure modes

### Backward Compatibility

None by design. This branch establishes an SDL-only boundary:
- Legacy APTL scenario YAMLs no longer parse through the SDL
- `aptl.core.scenarios` remains only as a thin loader/error module
- The old scenario CLI/API/runtime entrypoints were removed rather than left as partial shims

## Consequences

### Positive

- **19 real-world scenarios validated** from 8 platforms (OCR, CybORG, CALDERA, Atomic Red Team, CyRIS, KYPO, HTB, Locked Shields)
- **1,050+ fuzz test inputs** with zero unhandled crashes
- Every SDL element traces to a published precedent
- Backend-agnostic: no Docker, OpenStack, or cloud provider coupling
- The OCR-derived coverage gaps identified in branch review were closed: entity facts and orchestration time grammar now align with the verified OCR surface
- One clear specification surface for follow-on provisioner/runtime work

### Negative

- 24 source files in `aptl.core.sdl/` — significant surface area
- Variables (`${var}`) are still unresolved at parse time; existence is checked, but backend substitution semantics remain future work
- Existing APTL scenario YAMLs require migration to SDL format
- No module composition system yet (Terraform-style imports)
- No formal verification (VSDL's SMT / CRACK's Datalog)
- Agent action semantics are strings, not typed operations

### Risks

- The SDL was designed and tested by one system (this project). Practitioner feedback may reveal ergonomic issues or missing concepts
- The relationship model uses a flat `properties` dict which could become a maintenance burden as relationship types proliferate
- Variable resolution semantics are undefined — instantiation backends will need to agree on substitution rules
