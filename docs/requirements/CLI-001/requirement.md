---
id: CLI-001
title: "Lab Start/Stop/Status Commands"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:33.141793Z
updated_at: 2026-03-20T06:18:11.648778Z
---

# CLI-001: Lab Start/Stop/Status Commands

## Statement

The CLI shall provide aptl lab start, aptl lab stop, and aptl lab status commands for complete lab lifecycle management, including profile-aware container orchestration.

## Rationale

Lab lifecycle is the most fundamental operation.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-007-python-cli-control-plane.md` (ADR-007: Python CLI Control Plane)
- IMPLEMENTS → GITHUB_ISSUE `1000` (Release-blocking lab startup and status correctness)
- IMPLEMENTS → GITHUB_ISSUE `958` (Observed lab execution boundary and limits)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_project_inventory.py` (Checked all-state project container inventory)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/errors.py` (Typed project-inventory observation failure)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_content_mounts.py` (Repeatable generated bind-mount content realization)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Configured status selection and terminal startup attestation)
- IMPLEMENTS → CODE_FILE `src/aptl/core/execution_boundary.py` (Selected-daemon boundary observation)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab_types.py` (Startup boundary result carrier)
- IMPLEMENTS → CODE_FILE `src/aptl/core/snapshot.py` (Terminal container evidence persistence)
- IMPLEMENTS → CODE_FILE `src/aptl/cli/lab.py` (Status rendering for running and stopped inventory)
- IMPLEMENTS → CODE_FILE `src/aptl/cli/lab_render.py` (Start and info boundary presentation)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/_raes_provisioner_start.py` (Run-specific RAES apply disclosure)
- IMPLEMENTS → CODE_FILE `src/aptl/api/routers/lab.py` (Complete lab-status change projection)
- TESTS → TEST `tests/test_deployment_backend.py` (Project inventory ownership, state, and failure coverage)
- TESTS → TEST `tests/test_env_pack_realization.py` (Repeatable and symlink-safe content realization coverage)
- TESTS → TEST `tests/test_lab.py` (Status selection and terminal startup outcome coverage)
- TESTS → TEST `tests/test_snapshot.py` (Terminal inventory snapshot reuse coverage)
- TESTS → TEST `tests/test_cli.py` (Stopped-container status projection coverage)
- TESTS → TEST `tests/test_execution_boundary.py` (Selected transport, unknown, seat, and disclosure coverage)
- TESTS → TEST `tests/test_raes_backend.py` (RAES disclosure contract coverage)
- TESTS → TEST `tests/test_api_lab.py` (Same-container state-transition event coverage)
