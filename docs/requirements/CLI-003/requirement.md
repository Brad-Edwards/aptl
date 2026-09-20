---
id: CLI-003
title: "Ordered Lab Startup Sequence with Classified Failure Policy"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 1
created_at: 2026-03-20T06:09:40.330915Z
updated_at: 2026-09-14T00:00:00.000000Z
---

# CLI-003: Ordered Lab Startup Sequence with Classified Failure Policy

## Statement

`aptl lab start` shall run the applicable startup steps serially, in the fixed order `_LAB_START_STEPS` defines, while holding the project lifecycle lock. An admitted project-tree scenario retains the qualified legacy steps. An environment pack runs optional setup, readiness, retry, and MCP steps only when its exact selected startup adapter declares those capabilities. The order shall preserve these invariants:

1. **Admission before preparation.** Strict configuration and scenario-source selection precede source-specific environment loading. Legacy Wazuh credential hydration and secret validation run only for a source that needs them. The deployment backend and RAES scenario admission complete before any host artifact is prepared. Startup then refuses a project whose runtime residue already exists, or whose runtime presence the backend cannot observe.
2. **Pre-flight before realization.** Host port resolution and bind-mount validation run before realization starts any range container. The SSH control-plane key, host requirements (`vm.max_map_count` and Docker Buildx), credentialized service config, Suricata runtime volumes, Wazuh and SOC certificates, and image pre-pull run before realization when selected. Material that the admitted scenario declares as a generated artifact is produced during realization, not by these host-side steps.
3. **One realization boundary.** Containers start only through the RAES handoff (`start_raes_scenario` → `DeploymentBackend.realize`), which applies the scenario admitted in invariant 1 without planning it again. For Wazuh services that consume a scenario-declared generated artifact, the backend's authenticated-readiness gate proves readiness inside realization.
4. **Readiness after realization.** When selected, Wazuh indexer and manager API services that the backend didn't prove are polled after realization, followed by SSH reachability probes for the interactive targets the realization declares.
5. **Enrichment after readiness.** Selected terminal SSH host-key pinning, MCP build, SOC seeding, and MCP client config sync run after readiness, with SOC seeding before MCP client config sync.
6. **Attestation before evidence.** Terminal project-container attestation runs before range snapshot capture, and snapshot capture runs before the run reproducibility record is written.

Failure handling shall follow ADR-030:

- **Fatal.** These failures stop the sequence at the failing step and report outcome `failed`: any failure of invariants 1 through 3 except an image pre-pull miss outside offline-staged mode; Wazuh readiness failure when the Wazuh readiness capability is selected, whether the backend gate or the lab readiness wait observes it; terminal attestation that finds a non-running project container, finds no project containers, or can't observe container state; and a contract violation in any step. The RAES handoff may retry one retryable backend-start failure for a plan that selects SOC and has a qualified repair callback before the failure becomes fatal.
- **`degraded_unusable`.** These failures don't stop the sequence and are reported as readiness or capability diagnostics: an unreachable SSH target, an MCP build failure, a SOC seeding failure or an incomplete prime profile set for seeding, and an MCP client config sync failure.
- **`degraded_usable`.** These failures don't stop the sequence and are reported as telemetry diagnostics: range snapshot capture failure and run reproducibility record write failure.
- **No outcome change.** An image pre-pull miss outside offline-staged mode is an informational cosmetic diagnostic, and a terminal host-key pinning failure is logged only.

A startup that completes with no warning- or error-severity diagnostic shall report outcome `ready`.

## Rationale

Startup order carries hard dependencies. Admission decides which scenario, profiles, and generated artifacts the run realizes, so every later pre-flight check reads the admitted realization rather than guessing from config flags. Pre-flight failures are cheap to fix before containers start and expensive to diagnose after. Realization is the single point where containers start, and readiness, enrichment, attestation, and evidence capture each depend on what came before.

Not every failure is equal. A scenario that selects Wazuh can't meet its goals without the SIEM, and a lab with non-running project containers isn't the range the scenario declared, so both fail startup. SSH, MCP, and SOC seeding gaps leave a running range that can't do its job until an operator acts, while snapshot and run record gaps only reduce the evidence trail. ADR-030 makes that distinction machine-readable so automation doesn't have to scrape logs to trust a startup.

## Traceability

- IMPLEMENTS → ADR `docs/adrs/adr-007-python-cli-control-plane.md` (ADR-007: Python CLI Control Plane)
- IMPLEMENTS → ADR `docs/adrs/adr-030-startup-partial-readiness-classification.md` (ADR-030: Startup Partial-Readiness Classification)
- IMPLEMENTS → CODE_FILE `src/aptl/core/lab.py` (Ordered `_LAB_START_STEPS`, fatal short-circuit, and ADR-030 outcome derivation)
- IMPLEMENTS → CODE_FILE `src/aptl/backends/scenario_startup.py` (Validated exact adapter capabilities for optional lifecycle stages)
- IMPLEMENTS → CODE_FILE `src/aptl_techvault/startup.py` (Qualified TechVault setup, retry, and MCP selections)
- IMPLEMENTS → CODE_FILE `src/aptl/core/services.py` (Indexer and phased manager API readiness probes)
- IMPLEMENTS → CODE_FILE `src/aptl/core/deployment/_compose_stateful_readiness.py` (Fail-closed authenticated Wazuh readiness inside realization)
- TESTS → TEST `tests/test_lab.py` (Step order, fatal short-circuit, and degraded outcome classification)
- TESTS → TEST `tests/test_lab_lifecycle_selection.py` (Selected stages, adapter-free environment, cancellation, and bounded seed environment)
- TESTS → TEST `tests/test_services.py`
- TESTS → TEST `tests/test_deployment_stateful_realization.py`
