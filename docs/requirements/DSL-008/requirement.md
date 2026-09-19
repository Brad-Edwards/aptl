---
id: DSL-008
title: "APTL Realization of ACES Infrastructure Topology"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-24T02:44:23.438740Z
updated_at: 2026-09-04T00:00:00.000000Z
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
- IMPLEMENTS → CODE_FILE `src/aptl/backends/_raes_scenario_queries.py` (Admit one scenario execution; project the pre-start facts lab start reads)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_runtime_observation.py` (Trusted observation of declared runtime concerns on the realized range)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/_runtime_concern_excess.py` (Excess/scope detection and the runtime baselines subtracted before rejection)
- TESTS → TEST `tests/test_raes_runtime_observation.py` (Realization-observation gate tests, including the runtime-baseline carve-outs)
- IMPLEMENTS → GITHUB_ISSUE `956` (Faithfully realize SDL privilege and runtime security requirements)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/runtime_materialization.py` (Graph-wide pre-mutation qualification of image-backed, generic, mixed, mount, and orchestration-authority contracts)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_node_generation.py` (Faithful Compose lowering for supported runtime container, capability, and mount fields)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_realization.py` (Qualification and effective-model gates before ownership or deployment mutation)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes.py` (Read-only planned-graph qualification before deferred component-image materialization)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_artifact_availability.py` (Read-only specification inspection separated from post-qualification Docker builds)
- IMPLEMENTS → DOCUMENTATION `docs/architecture/issue-956-sdl-runtime-authority-materialization-preflight.md` (Faithful runtime-authority materialization boundary and supported backend fields)
- TESTS → TEST `tests/test_runtime_materialization.py` (Supported and unsupported materialization, lowering, ordering, and effective-model coverage)
- TESTS → TEST `tests/test_raes_artifact_availability.py` (Read-only inspection and deferred component-build ordering coverage)
- TESTS → TEST `tests/test_raes_runtime_orchestration.py` (Exact raw-socket joins and unrestricted authored holder topology coverage)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/scenario_startup_policy.py` (Pack-qualified, declared-edge-only startup health policy)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_model_realization.py` (Validated startup overlay in the generated Compose file set)
- IMPLEMENTS → CODE_FILE `src/aptl_techvault/startup.py` (TechVault-specific health probes through the adapter seam)
- TESTS → TEST `tests/test_techvault_startup_adapter.py` (Content-qualified startup policy and undeclared-edge rejection)
- TESTS → TEST `tests/test_imagefree_admission_integration.py` (Product-neutral real-Docker materialization envelope)
