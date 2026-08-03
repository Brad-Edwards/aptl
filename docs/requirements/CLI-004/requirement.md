---
id: CLI-004
title: "Container List, Shell, and Logs Commands"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 1
created_at: 2026-03-20T06:09:43.074351Z
updated_at: 2026-03-20T06:18:11.648844Z
---

# CLI-004 — Container List, Shell, and Logs Commands

## Statement

The CLI shall provide aptl container list, aptl container shell, and aptl container logs commands for inspecting and interacting with running lab containers.

## Rationale

Users need to inspect container state and access shells without manually constructing Docker commands.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/cli/container.py` (aptl container list/shell/logs commands)
- IMPLEMENTS → CODE_FILE `src/aptl/cli/_common.py` (resolve_config_for_cli helper)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/backend.py` (DeploymentBackend Protocol with container interaction methods)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/docker_compose.py` (DockerComposeBackend container_list/shell/logs implementation)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/ssh_compose.py` (SSHComposeBackend env injection for streaming + captured paths)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/errors.py` (BackendTimeoutError)
- IMPLEMENTS → ADR `docs/adrs/adr-023-container-interaction-in-deployment-backend.md` (ADR-023: Container interaction on the DeploymentBackend Protocol)
- TESTS → TEST `tests/test_cli_container.py` (CLI container list/shell/logs tests)
- TESTS → TEST `tests/test_deployment_backend.py` (DeploymentBackend Protocol tests (container + host inventory))
- IMPLEMENTS → GITHUB_ISSUE `138` (Issue 138 — implement stubbed CLI commands)
