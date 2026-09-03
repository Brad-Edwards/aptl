---
id: DEP-001
title: "Cloud-Native Deployment Abstraction"
status: ACTIVE
type: NON_FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-03-21T07:53:40.464228Z
updated_at: 2026-03-22T04:01:17.309848Z
---

# DEP-001: Cloud-Native Deployment Abstraction

## Statement

The platform shall provide a deployment abstraction layer enabling deployment beyond a single Docker host (supporting container orchestration, cloud VMs, or hybrid models) without requiring changes to scenario definitions or MCP server configurations.

## Rationale

Single-host Docker Compose is a deployment constraint, not an architectural requirement. A deployment abstraction enables scaling to classroom, team, and enterprise deployments. KYPO uses OpenStack, SCORPION uses Terraform+Ansible.

## Traceability

- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/docker_compose.py` (DockerComposeBackend implementation)
- DOCUMENTS → ADR `docs/adrs/adr-013-deployment-abstraction.md` (ADR-013: Deployment Backend Abstraction Layer)
- DOCUMENTS → GITHUB_ISSUE `233` (DEP-001: Cloud-Native Deployment Abstraction)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/backend.py` (DeploymentBackend Protocol)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/ssh_compose.py` (SSHComposeBackend implementation)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/__init__.py` (Deployment factory and package init)
- TESTS → TEST `tests/test_deployment_backend.py` (Deployment backend tests (52 tests))
- DOCUMENTS → GITHUB_ISSUE `307` (K8s deployment backend: implement DeploymentBackend Protocol against any Kubernetes cluster)
- DOCUMENTS → GITHUB_ISSUE `308` (K8s deployment recipes: multi-cloud provisioning tracker (EKS / GKE / AKS / on-prem))
- DOCUMENTS → ADR `docs/adrs/adr-023-container-interaction-in-deployment-backend.md` (ADR-023: Container interaction (list/logs/shell/exec/inspect) on the DeploymentBackend Protocol (extends ADR-013))
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/errors.py` (BackendTimeoutError exception class)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_image_fetch.py` (DockerComposeBackend image pre-fetch mixin (split from docker_compose.py for S104))
