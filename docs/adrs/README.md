# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for APTL. ADRs capture significant architectural decisions along with their context, rationale, and consequences.

## Format

We use [MADR](https://adr.github.io/madr/) (Markdown Any Decision Records). Each ADR includes:

- **Status**: `proposed`, `accepted`, `deprecated`, or `superseded by ADR-XXX`
- **Context**: The problem or situation driving the decision
- **Decision**: What we chose and why
- **Consequences**: Trade-offs (positive, negative, risks)

## Principles

- ADRs are **immutable** once accepted. To reverse a decision, create a new ADR that supersedes it.
- ADRs are **numbered sequentially** and never reused.
- ADRs are **versioned with code** — they live in the repo, not a wiki.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [000](adr-000-use-adrs.md) | Use Architecture Decision Records | accepted | 2026-03-20 |
| [001](adr-001-docker-compose-deployment.md) | Migrate from AWS/Terraform to Local Docker Compose | accepted | 2025-08-06 |
| [002](adr-002-wazuh-siem.md) | Wazuh SIEM over Splunk and qRadar | accepted | 2025-08-06 |
| [003](adr-003-mcp-common-library.md) | MCP Common Library with Config-Driven Server Generation | accepted | 2025-08-30 |
| [004](adr-004-persistent-ssh-sessions.md) | Persistent SSH Session Architecture with Command Queuing | accepted | 2025-08-30 |
| [005](adr-005-docker-compose-profiles.md) | Docker Compose Profiles for Selective Deployment | accepted | 2025-09-01 |
| [006](adr-006-four-network-segmentation.md) | Four-Network Segmentation Architecture | accepted | 2026-02-07 |
| [007](adr-007-python-cli-control-plane.md) | Python CLI as Primary Control Plane | accepted | 2026-02-07 |
| [008](adr-008-soc-stack-integration.md) | Integrated SOC Stack (MISP, TheHive, Cortex, Shuffle, Suricata) | accepted | 2026-02-22 |
| [009](adr-009-scenario-engine.md) | Scenario Engine with YAML Specs and Run Archive Collectors | accepted | 2026-03-02 |
| [010](adr-010-sonarcloud-quality.md) | SonarCloud for Continuous Code Quality | accepted | 2026-03-07 |
| [011](adr-011-web-ui.md) | Notebook-Style Web UI (SvelteKit + FastAPI) | proposed | 2026-03-20 |
| [012](adr-012-opentelemetry-integration.md) | OpenTelemetry Integration | accepted | 2026-03-21 |
| [013](adr-013-deployment-abstraction.md) | Deployment Backend Abstraction Layer | accepted | 2026-03-22 |
| [014](adr-014-scenario-description-language.md) | Scenario Description Language (SDL) | accepted | 2026-03-29 |
| [015](adr-015-declarative-sdl-objectives.md) | Declarative Experiment Objectives in the SDL | accepted | 2026-03-29 |
| [016](adr-016-workflows-targetable-subobjects-and-enum-variables.md) | Workflows, Targetable Sub-Objects, and Leaf Enum Variables in the SDL | accepted | 2026-03-29 |
| [017](adr-017-sdl-runtime-layer.md) | SDL Runtime Layer | proposed | 2026-03-30 |
| [018](adr-018-control-flow-primitives.md) | Control Flow Primitives in the SDL | superseded by ADR-019 | 2026-04-01 |
| [019](adr-019-workflow-control-language-redesign.md) | Workflow Control-Language Redesign | accepted | 2026-04-01 |
| [020](adr-020-lightweight-formal-methods-policy.md) | Lightweight Formal Methods Policy for Semantic Systems | accepted | 2026-04-01 |
