---
id: APP-2
title: "Versioned participant profile conformance"
status: ACTIVE
type: NON_FUNCTIONAL
priority: MUST
wave: 6
created_at: 2026-07-25T22:39:26.836288Z
updated_at: 2026-07-26T00:06:36.824860Z
---

# APP-2 — Versioned participant profile conformance

## Statement

APTL shall bind each supported participant delivery profile to a canonical narrative, admitted ACES scenario and configuration, staged asset lock, participant capability allow-lists, semantic readiness suite, explicit resource and lifecycle budgets, and a machine-readable qualification report; conformance shall fail on a missing or unexpected runtime surface, failed real backend operation, participant exposure of a disabled capability, unstaged network dependency, or budget breach.

## Rationale

Issue #820 defines the reusable bounded workshop/classroom profile and qualification contract consumed by the appliance artifact in issue #823. The contract must remain separate from ACES scenario meaning, operator configuration, Compose deployment grouping, and the ADR-049 appliance envelope while still producing reproducible release evidence.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/validation/participant_mcp_smoke.py` (Participant MCP semantic smoke collector)
- IMPLEMENTS → PULL_REQUEST `836` (PR #836: define bounded participant lab profile)
- TESTS → TEST `tests/test_participant_profile.py` (Participant profile conformance tests)
- TESTS → TEST `tests/test_participant_qualification.py` (Participant qualification trust and budget tests)
- TESTS → TEST `tests/test_participant_mcp_smoke.py` (Participant MCP semantic smoke tests)
- DOCUMENTS → DOCUMENTATION `docs/reference/participant-profile.md` (Participant profile reference)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/participant_profile.py` (Participant profile loader and conformance model)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/participant_qualification.py` (Authenticated participant qualification evaluator)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/participant_profile_models.py` (Participant profile contract models)
- IMPLEMENTS → CODE_FILE `src/aptl/validation/participant_qualification_evidence.py` (Authenticated qualification evidence loader)
- IMPLEMENTS → SPEC `participant-profiles/guided-purple-v1/narrative.json` (Guided-purple participant narrative)
- IMPLEMENTS → CONFIG `participant-profiles/guided-purple-v1/profile.json` (Guided-purple participant profile manifest)
- IMPLEMENTS → SPEC `participant-profiles/guided-purple-v1/readiness.json` (Guided-purple semantic readiness suite)
- IMPLEMENTS → CONFIG `participant-profiles/guided-purple-v1/asset-lock.json` (Guided-purple staged asset lock)
- TESTS → TEST `tests/test_mcp_protocol.py` (MCP protocol fail-closed tests)
- IMPLEMENTS → CODE_FILE `src/aptl/workbench/profiles.py` (Participant capability allow-list registry)
- IMPLEMENTS → GITHUB_ISSUE `820` (Issue #820: resource-bounded participant lab profile)
- TESTS → TEST `tests/test_participant_workbench.py` (Participant workbench profile tests)
