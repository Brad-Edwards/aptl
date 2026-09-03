---
id: APP-1
title: "Scenario-independent appliance boundary materialization"
status: ACTIVE
type: NON_FUNCTIONAL
priority: MUST
wave: 6
created_at: 2026-07-25T20:27:41.068600Z
updated_at: 2026-07-26T01:35:18.580567Z
---

# APP-1: Scenario-independent appliance boundary materialization

## Statement

The APTL backend shall materialize admitted ACES infrastructure ACLs and narrow appliance-platform boundary controls through typed, scenario-independent deployment contracts; fail closed when network, egress, Docker-authority, or host-exposure policy is unsupported or unverifiable; and produce a redacted observed inventory used by image qualification and every appliance start.

## Rationale

Issue #822 establishes the general materializability and qualification surface consumed by the disposable appliance artifact (#823) and host launcher (#824). Scenario topology and exercise effects remain authoritative in admitted ACES realization; the appliance platform policy must not duplicate current or future scenario nodes, networks, services, or zone membership.

## Traceability

- TESTS → TEST `tests/test_compose_platform_boundary.py` (Platform boundary enforcement tests)
- TESTS → TEST `tests/test_appliance_boundary_integration.py` (Boundary integration and live proof tests)
- TESTS → TEST `tests/test_network_boundary_helper.py` (Boundary helper lifecycle and drift tests)
- TESTS → TEST `tests/test_appliance_egress_proxy.py` (Controlled egress broker tests)
- DOCUMENTS → DOCUMENTATION `docs/components/appliance-boundary.md` (Appliance boundary authority and materialization reference)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/boundary.py` (Typed authority-preserving boundary contracts)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/boundary_compiler.py` (Scenario-independent boundary compiler)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_boundary_realization.py` (Compose boundary realization lifecycle)
- IMPLEMENTS → CODE_FILE `src/aptl/core/appliance_boundary_inventory.py` (Fatal observed boundary inventory and verdict)
- IMPLEMENTS → CODE_FILE `src/aptl/core/appliance_boundary.py` (Signed appliance boundary policy contract)
- IMPLEMENTS → CODE_FILE `src/aptl/core/appliance_boundary_gate.py` (Shared image-qualification and start verifier)
- IMPLEMENTS → CODE_FILE `containers/network-boundary-helper/helper.py` (External nftables boundary enforcement helper)
- IMPLEMENTS → GITHUB_ISSUE `822` (GitHub issue #822)
- IMPLEMENTS → CODE_FILE `containers/appliance-egress-proxy/proxy.py` (Controlled exact-authority egress broker)
- TESTS → TEST `tests/test_appliance_boundary_gate.py` (Shared qualification/start gate tests)
- TESTS → TEST `tests/test_appliance_boundary_inventory.py` (Fatal inventory and provenance tests)
- TESTS → TEST `tests/test_appliance_boundary_policy.py` (Signed platform policy tests)
- TESTS → TEST `tests/test_boundary_compiler.py` (Authority-preserving compiler tests)
- TESTS → TEST `tests/test_compose_boundary_realization.py` (Selected-daemon boundary lifecycle tests)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/realization.py` (Backend-neutral deployment realization contract)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_boundary.py` (Selected-daemon boundary helper lifecycle)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/backend.py` (Deployment boundary capability contract)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/docker_compose.py` (Compose boundary integration)
- IMPLEMENTS → CONFIG `containers/network-boundary-helper/Dockerfile` (Pinned boundary helper image)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_base_substrate.py` (Network-before-start base substrate realization)
- IMPLEMENTS → CONFIG `containers/appliance-egress-proxy/Dockerfile` (Pinned controlled egress image)
- TESTS → TEST `tests/test_compose_base_substrate.py` (Network-before-start substrate tests)
- TESTS → TEST `tests/test_mixed_realization_integration.py` (Mixed realization integration tests)
- TESTS → TEST `tests/test_raes_acl_realization.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_acl_realization.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization_model.py`
- TESTS → TEST `tests/test_raes_backend.py`
- IMPLEMENTS → CODE_FILE `src/aptl/backends/raes_realization.py`
- DOCUMENTS → DOCUMENTATION `docs/raes/app-1-appliance-boundary-materialization-preflight.md`
