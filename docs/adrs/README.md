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
- ADRs are **versioned with code**—they live in the repo, not a wiki.

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
| [018](adr-018-control-flow-primitives.md) | Control Flow Primitives in the SDL | accepted | 2026-04-01 |
| [019](adr-019-suricata-ids-only-prevention-via-wazuh-ar.md) | Suricata stays IDS-only; packet-level prevention via Wazuh active-response | accepted | 2026-05-02 |
| [020](adr-020-wazuh-agents-in-process-vs-sidecar.md) | Wazuh agents run in-process on target containers; sidecars only for upstream-image carve-outs | accepted | 2026-05-02 |
| [021](adr-021-active-response-whitelist-via-wrapper.md) | Active-response whitelist enforcement via a standalone iptables AR script | accepted | 2026-05-02 |
| [022](adr-022-misp-driven-suricata-rules.md) | MISP-driven Suricata rules via a tag-graduated sync service | accepted | 2026-05-03 |
| [023](adr-023-container-interaction-in-deployment-backend.md) | Container interaction (list/logs/shell/exec/inspect) on the DeploymentBackend Protocol | accepted | 2026-05-03 |
| [024](adr-024-orchestrator-side-purple-continuity-carve-out.md) | Orchestrator-side purple-team continuity carve-out | accepted | 2026-05-03 |
| [025](adr-025-strict-first-party-config-schema.md) | Strict first-party config schema | accepted | 2026-05-05 |
| [026](adr-026-advisory-ci-vulnerability-scanning.md) | Advisory CI Vulnerability Scanning | accepted | 2026-05-09 |
| [027](adr-027-red-team-structured-logging.md) | Red Team Structured Logging Boundary (SIEM-transport superseded by ADR-033) | accepted (amended) | 2026-05-09 |
| [028](adr-028-runtime-rendered-service-config.md) | Runtime-Rendered Service Config | accepted | 2026-05-10 |
| [029](adr-029-control-plane-secret-handling.md) | Control-Plane Secret Handling in Run Data and Local State | accepted | 2026-05-10 |
| [030](adr-030-startup-partial-readiness-classification.md) | Startup Partial-Readiness Classification | accepted | 2026-05-11 |
| [031](adr-031-lab-orchestration-contract-guards.md) | Lab Orchestration Contract Guards | accepted | 2026-05-12 |
| [032](adr-032-conversation-surface-hardening.md) | Conversation Surface Hardening | accepted | 2026-05-17 |
| [033](adr-033-agent-reasoning-trace-boundary.md) | Red-Side Behavioural Capture and Non-Contamination Boundary | accepted | 2026-05-17 |
| [034](adr-034-lab-managed-soc-tls-ca.md) | Lab-Managed CA for Verified SOC Stack TLS | accepted | 2026-05-18 |
| [035](adr-035-aces-sdl-adoption.md) | Adopt ACES SDL as APTL's Scenario Authoring Surface | accepted | 2026-05-18 |
| [036](adr-036-snapshot-endpoint-registry.md) | Snapshot Endpoint Registry Boundary | accepted | 2026-05-18 |
| [037](adr-037-docker-compose-backend-cohesion.md) | Docker Compose Backend Cohesion | accepted | 2026-05-18 |
| [038](adr-038-docs-style-lint-and-published-site.md) | Documentation Style Lint and Published Docs Site | accepted | 2026-06-11 |
| [039](adr-039-web-control-plane-authentication.md) | Web Control Plane Authentication and Loopback Exposure | accepted | 2026-06-14 |
| [040](adr-040-terminal-ssh-host-key-verification.md) | Terminal SSH Host-Key Verification Boundary | accepted | 2026-06-13 |
| [041](adr-041-kali-capture-sidecar-ownership-boundary.md) | Kali Capture Sidecar Ownership Boundary (PTY-typescript residual superseded by ADR-042) | accepted (amended) | 2026-06-20 |
| [042](adr-042-sidecar-owned-pty-master.md) | Sidecar-Owned PTY Master for Kali Transcript Authenticity | accepted | 2026-06-20 |
| [043](adr-043-suricata-runtime-config-ownership-boundary.md) | Suricata Runtime Config Ownership Boundary | accepted | 2026-06-20 |
| [044](adr-044-aces-aligned-run-reproducibility-record.md) | ACES-Aligned Run Reproducibility Record | accepted | 2026-06-25 |
| [045](adr-045-composite-mcp-tools.md) | Composite MCP Tool Orchestration Boundary | accepted | 2026-06-28 |
