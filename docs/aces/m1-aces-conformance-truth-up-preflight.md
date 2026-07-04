# M1 ACES Conformance Truth-Up Preflight

This note is the architecture preflight for issue #599. It is guidance, not an
implementation plan. ADR-035 remains the binding ACES adoption decision,
ADR-046 remains the dynamic realization decision, and ADR-044 remains the run
record boundary. This note narrows the guardrails for making APTL's
`full-remote-control-plane` backend claim honest end to end.

## Architecture Decisions

- Treat M1 as a contract-honesty and live-proof milestone, not a new backend
  framework. APTL already has one ACES runtime target:
  `create_aptl_runtime_target()` with `AptlProvisioner`, `AptlOrchestrator`,
  `AptlEvaluator`, and `AptlParticipantRuntime`.
- `create_aptl_manifest()` is the only APTL source for the published backend
  manifest. Do not add a checked-in manifest JSON, local capability schema, or
  profile-specific shim.
- Contract-first ordering is mandatory. A capability, controlled-vocabulary
  term, contract id, score field, participant behavior feature, or profile
  requirement must exist in the ACES repo/package before APTL references it.
  APTL consumes ACES authorities; it does not front-run them.
- A manifest capability is valid only when the same target realizes it through
  live infrastructure or a contract-clean control-plane path. Conformance is a
  verification boundary, not an assertion boundary.
- Evaluation progression must be truthful. `AptlEvaluator` may publish
  `PENDING`, `RUNNING`, terminal outcome, and score/progress fields only when
  those values are driven from real RTE-001 objective/evaluation execution or
  from an upstream ACES evaluation contract that defines the field.
- Participant runtime live actions must be compiled-artifact and realization
  driven. The legacy `DEFAULT_PARTICIPANT_ACTIONS` TechVault probe can remain a
  compatibility fallback, but new live conformance behavior must use
  `participant_action_specs_for_scenario()` and the interpreted realization
  context rather than more hardcoded scenario branches.
- Documentation truth-up is part of the contract surface. Current docs,
  adapter docstrings, preflight notes, CI labels, and gate names must either
  name `full-remote-control-plane` as the current claim or clearly mark older
  `provisioning-only`, `orchestration-capable`, and
  `orchestration-evaluation` text as historical.

## Required Cross-Cutting Concerns

- ACES authorities: `aces_sdl.parse_sdl_file`, `compile_runtime_model`,
  `RuntimeManager`, `RuntimeControlPlane`, `RuntimeTarget`, `ExecutionPlan`,
  `BackendManifest`, `backend_manifest_payload()`, `run_target_conformance()`,
  `aces conformance backend --profile full-remote-control-plane`, and ACES
  contract dataclasses for diagnostics, runtime snapshots, workflow,
  evaluation, and participant runtime.
- APTL ACES seams: `src/aptl/backends/aces.py`,
  `aces_manifest.py`, `aces_diagnostics.py`, `aces_realization.py`,
  `aces_realization_model.py`, `aces_profiles.py`, `aces_orchestrator.py`,
  `aces_evaluator.py`, `aces_participant_runtime.py`,
  `aces_participant_actions.py`, and `aces_participant_bindings.py`.
- Runtime execution owners: `aptl.core.runtime.workflow_engine.WorkflowEngine`
  for workflow progression and objective outcome propagation; do not publish
  `aptl.core.runtime` records as ACES DTOs.
- Deployment owners: `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, `ComposeRealizationMixin`, `ComposeQueryMixin`,
  project-name scoping, compose-project label filters, bounded
  `container_exec()`, and typed image/network realization methods.
- Config and secret owners: strict `AptlConfig`, `DeploymentConfig`,
  `ContainerSettings.enabled_profiles()`, `load_config()`, `load_dotenv()`,
  `env_vars_from_dict()`, `find_placeholder_env_values()`, ADR-028 generated
  config, ADR-029 secret handling, and ADR-034 SOC TLS material.
- Persistence and evidence owners: `LocalRunStore.write_json()` /
  `write_jsonl()` / `append_jsonl()`, `RangeSnapshot.to_dict()`,
  `build_reproducibility_record()`, `AptlRealization.details()`, and existing
  curated/live-gate evidence directories.
- Validation and workflow gates: `src/aptl/validation/techvault_gate.py`,
  `src/aptl/validation/_gate_checks.py`,
  `src/aptl/validation/techvault_live_gate.py`, `_live_gate_checks.py`,
  `tests/test_aces_backend.py`, `tests/test_aces_evaluator.py`,
  `tests/test_aces_orchestrator.py`, `tests/test_techvault_static_gate.py`,
  `.pre-commit-config.yaml`, and `.github/workflows/checks.yml`.

## Security And Validation Layers

- **ACES parser/compiler gate:** authored scenarios enter through ACES parsing,
  import verification, semantic compilation, planner diagnostics, and runtime
  manager planning. APTL must not add local SDL, capability, workflow,
  evaluation, participant, or scoring mirror schemas.
- **Manifest/profile gate:** `create_aptl_manifest()` must serialize through
  `backend_manifest_payload()` and pass both `run_target_conformance()` and the
  published CLI profile. Missing ACES corpus/profile/CLI support is a failure,
  not a waiver.
- **Runtime target gate:** the target components must match the manifest:
  provisioner, orchestrator, evaluator, and participant runtime all present,
  method-compatible, and returning ACES `ApplyResult` / `RuntimeSnapshot`
  payloads.
- **Evaluation envelope gate:** result and history state must use ACES
  evaluation dataclasses and diagnostics. Do not fabricate score progression,
  terminal outcomes, or history events to satisfy conformance.
- **Participant envelope gate:** episode state/history, behavior history,
  shared state records, action contracts, and observation boundaries must use
  ACES participant contracts and snapshot validators. A successful command exit
  is not enough without contract-clean snapshot state.
- **Deployment and OS exposure gate:** live actions, Docker, Compose, image,
  network, container, and host operations stay behind `DeploymentBackend`.
  Commands are argv lists with bounded timeouts. Do not pass tokens,
  passwords, cookies, private keys, generated config, or rendered secret values
  in argv, shell strings, URLs, logs, diagnostics, or persisted proof JSON.
- **Config/env binding gate:** durable non-secret knobs belong in strict
  `AptlConfig`; runtime secrets belong in `.env` / `EnvVars` with placeholder
  checks. Diagnostics may name a variable, never its value.
- **Isolation gate:** shared-daemon operations must remain project-scoped by
  compose project labels and configured project name. Do not inspect or act on
  unscoped `aptl-*` containers or networks.
- **Error-envelope gate:** ACES-facing failures are ACES `Diagnostic` records
  and operation-status details. APTL-facing failures remain `LabResult`,
  `StartupDiagnostic`, `GateReport`, `LiveGateReport`, API schemas, or pytest
  assertions. Every message crossing CLI/API/log/persistence boundaries must be
  redacted with the existing redactor.
- **Persistence gate:** structured conformance, live-proof, snapshot, and run
  evidence uses `LocalRunStore` JSON/JSONL writers or existing redacted
  snapshot summaries. `write_file()` / `copy_file()` are inappropriate for
  secret-shaped structured data because they are intentionally pass-through.
- **API/auth gate:** if any new proof or status surface is exposed through the
  web API, it must use `verify_token`, `WebAuthSettings`, BFF CSRF/host gates,
  and narrow Pydantic response projections. Do not expose raw ACES objects or
  internal paths directly.

## Extensibility Seam

The seam is:

`(scenario_path, backend_profile, target_name, manifest_contract_versions,
execution_plan, realization_details, participant_action_descriptor,
evaluation_address, objective_address, run_id, deployment_backend_provider)`.

The next reasonable variation is another scenario, participant action,
evaluation resource, or deployment provider. That should require adding a
validated descriptor or typed backend parameter, not editing a TechVault branch,
forking the manifest generator, adding a new conformance runner, or copying
ACES schemas into APTL.

## Whole-Repo View

- Canonical configs: `.ground-control.yaml`, `.gc/plan-rules.md`,
  `pyproject.toml`, `.pre-commit-config.yaml`, `.github/workflows/checks.yml`,
  `aptl.json` via `AptlConfig`, `.env` via `EnvVars`, and
  `docker-compose.yml`.
- Canonical scripts/commands: `pytest`, `pre-commit run --all-files`,
  manual `pre-commit run aces-scenario-gate --hook-stage manual`, and
  `aces conformance backend --profile full-remote-control-plane`.
- Canonical docs/records: ADR-035, ADR-044, ADR-046, this note,
  `docs/aces/parity-inventory.yaml`, static/live validation gate docs, and
  adapter docstrings.
- Runtime layers touched: ACES parser/compiler/planner/control plane, APTL
  ACES adapters, lab lifecycle, deployment backend, Docker/SSH Compose runner,
  container exec, snapshot capture, runstore persistence, API/auth if exposed,
  and CI/pre-commit gates.

## Gotchas And Anti-Patterns

- Declaring a manifest capability because conformance only checks component
  shape, while live infrastructure cannot realize it.
- Adding unsupported contract ids or vocabulary tokens locally before ACES
  publishes them upstream.
- Keeping adapter docstrings or docs that still describe APTL as merely
  orchestration-capable without a historical label.
- Treating evaluator registration as live score progression.
- Treating participant episode lifecycle calls as lab start/stop operations.
- Extending `DEFAULT_PARTICIPANT_ACTIONS` as the primary design instead of
  using runtime-derived action bindings.
- Calling raw `docker`, `docker compose`, `curl`, or `ssh` from ACES adapters
  or proof code.
- Creating duplicate DTOs, schemas, validation helpers, exception hierarchies,
  redaction helpers, conformance scripts, run manifests, readiness taxonomies,
  or API projections.
- Branching on `techvault`, file names, compose profiles, or catalog ids inside
  canonical adapter logic.
- Flattening ACES workflow/evaluation/participant histories into summaries
  before ACES validation and persistence boundaries have handled them.

## Non-Goals

- Do not implement issue #599 in this preflight.
- Do not define new ACES contracts, profiles, controlled vocabulary, or
  scenario language in APTL.
- Do not redesign `RuntimeControlPlane`, `RuntimeTarget`, `DeploymentBackend`,
  Docker Compose topology, startup ordering, generated config, SOC TLS, web
  auth, terminal relay, snapshot registry, or run archive layout.
- Do not make participant runtime a general shell-execution API.
- Do not make evaluator scoring a simulated state machine detached from real
  objective/evaluation observations.
- Do not replace the static/live gates with a new M1-specific gate. Extend the
  existing gate owners and profile parameters when implementation begins.
