---
id: DSL-008
title: "APTL Realization of ACES Infrastructure Topology"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-24T02:44:23.438740Z
updated_at: 2026-06-25T01:41:02.775104Z
---

# DSL-008: APTL Realization of ACES Infrastructure Topology

## Statement

The APTL backend shall consume ACES parser/compiler output and declared topology/runtime-model content for containers, Compose profiles, networks, services, addresses, volumes, health checks, and supported topology transitions. Before scenario execution, it shall validate that the running lab satisfies those declarations, realize supported changes through model/plan-driven Docker Compose operations, and fail with explicit diagnostics for unsupported or missing declarations instead of dispatching on scenario name or maintaining an APTL-local scenario DSL.

## Rationale

After ADR-035 and SCN-010, ACES SDL owns scenario authoring and topology declaration. APTL's Wave 1 responsibility is the backend realization contract: map ACES runtime/provisioning content to the local Docker lab without reviving aptl.core.sdl or a TechVault preset shortcut.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#422` (DSL-008: Infrastructure Topology Declaration in Scenario DSL)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/techvault_live_gate.py` (Live conformance gate: validate the running lab satisfies ACES declarations)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/_live_gate_readiness.py` (Node-readiness / declared-health conformance comparison against the running range)
- TESTS → TEST `tests/test_techvault_live_gate.py` (Tests for live conformance gate incl. declared-health readiness enforcement)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization_values.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_profiles.py`
- TESTS → TEST `tests/test_raes_backend.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization_model.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_diagnostics.py`
