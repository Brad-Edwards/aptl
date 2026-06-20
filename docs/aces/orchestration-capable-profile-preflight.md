# ACES Orchestration-Capable Profile Preflight

This note is the architecture preflight for SCN-010 follow-on issue #311. It
is guidance, not an implementation plan. ADR-035 remains the binding ACES SDL
adoption decision, and the TechVault static and live preflight notes remain the
validation-shape precedents.

## Architecture Decisions

- Treat #311 as a backend profile promotion and ACES contract adapter change,
  not as a new APTL scenario runtime. APTL's published backend boundary must be
  ACES `backend-manifest-v2`, ACES `RuntimeTarget`, and the ACES orchestrator
  protocol.
- The manifest remains the canonical ACES
  `aces_backend_protocols.capabilities.BackendManifest` /
  `BackendCapabilitySet` payload. Promotion to `orchestration-capable` requires
  a real `OrchestratorCapabilities` declaration and the profile-required
  contracts `workflow-result-envelope-v1` and
  `workflow-history-event-stream-v1`; declare only workflow features and state
  predicates the APTL adapter actually supports.
- The APTL runtime target must carry a concrete orchestrator component
  satisfying ACES `Orchestrator.start()`, `status()`, `results()`,
  `history()`, and `stop()`. Conformance must fail if the target declares
  orchestration but publishes only provisioning.
- Workflow results and history are ACES contract surfaces. Populate
  `RuntimeSnapshot.orchestration_results` and
  `RuntimeSnapshot.orchestration_history` with ACES workflow-address-keyed
  `WorkflowExecutionState` and `WorkflowHistoryEvent` payloads validated by
  `aces_runtime.workflow_result_contracts.workflow_result_contract_diagnostics`.
- Existing APTL state-machine, session, run-archive, and legacy
  `aptl.core.runtime` models may inform internal execution, but they are not
  the public ACES DTOs and must not become a second workflow schema.
- Static and live gates remain the canonical validation homes. Upgrade the
  existing profile parameter, conformance calls, tests, pre-commit hook, and CI
  gate from `provisioning-only` to `orchestration-capable`; do not add a second
  conformance runner or report taxonomy.
- Once APTL claims orchestration, public scenario start must go through the
  ACES manager/target orchestration path. Do not keep the direct
  provisioning-only `AptlProvisioner.apply()` bypass or broad
  `evaluator.missing` allowlist as the normal start route.

## Cross-Cutting Concerns To Reuse

- ACES authorities: `RuntimeManager`, `RuntimeTarget`, `OrchestrationPlan`,
  `ApplyResult`, `RuntimeSnapshot`, `WorkflowExecutionState`,
  `WorkflowHistoryEvent`, `OrchestratorCapabilities`, `BackendCapabilitySet`,
  `backend_manifest_payload()`, backend profile JSON under
  `contracts/profiles/backend/`, `workflow_result_contract_diagnostics()`, and
  `aces conformance backend --profile orchestration-capable`.
- APTL ACES adapter seams: `src/aptl/backends/aces.py`,
  `src/aptl/backends/aces_manifest.py`,
  `src/aptl/backends/aces_diagnostics.py`,
  `src/aptl/backends/aces_realization.py`,
  `src/aptl/backends/aces_realization_model.py`,
  `src/aptl/backends/aces_realization_values.py`, and
  `src/aptl/backends/aces_profiles.py`.
- Lab and deployment owners: `orchestrate_lab_start()`, `stop_lab()`,
  `_LAB_START_STEPS`, `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, `LabResult`, `StartupOutcome`, and
  `StartupDiagnostic`.
- Config and environment owners: `AptlConfig`, `ContainerSettings`,
  `DeploymentConfig`, `load_config()`, `load_dotenv()`, `EnvVars`,
  `env_vars_from_dict()`, and `find_placeholder_env_values()`.
- Evidence and persistence owners: `RangeSnapshot.to_dict()`,
  `LocalRunStore`, `resolve_run_store()`, `collect_*` helpers,
  `curl_safe.curl_json()`, `aptl.utils.redaction.redact()`, and
  `aptl.utils.logging.get_logger()`.
- Validation and workflow gates: `src/aptl/validation/techvault_gate.py`,
  `src/aptl/validation/_gate_checks.py`,
  `src/aptl/validation/techvault_live_gate.py`,
  `src/aptl/validation/_live_gate_checks.py`,
  `tests/test_aces_backend.py`, `tests/test_techvault_static_gate.py`,
  `tests/test_techvault_live_gate.py`, `.pre-commit-config.yaml`, and
  `.github/workflows/checks.yml`.

## Security And Validation Layers

- **ACES SDL and plan shape:** scenario input still passes through the ACES
  parser, import verification, semantic validation, runtime model compiler,
  planner, and manager. APTL must not add local Pydantic workflow mirrors or
  scenario-name switches to satisfy orchestration.
- **Backend manifest and profile shape:** the manifest must serialize through
  ACES `backend_manifest_payload()` and pass the canonical
  `orchestration-capable` profile. Missing profile files, fixture corpus,
  conformance CLI, or required contracts are hard failures, not warnings.
- **Orchestrator protocol shape:** `RuntimeTarget` registry and ACES backend
  call adapters own the component boundary. The target must include an
  orchestrator object, and returned `ApplyResult` / `RuntimeSnapshot` data must
  remain ACES-shaped instead of APTL-native dictionaries.
- **Workflow result and history shape:** use ACES workflow contract models and
  diagnostics for result envelopes, event streams, status transitions, attempt
  counts, and workflow addresses. Do not flatten workflow history into run
  archive summaries before ACES validation has passed.
- **Config shape:** durable knobs stay in strict `AptlConfig`. Profile choice
  is a gate/runtime parameter, not a new unchecked `aptl.json` dictionary or a
  value inferred from `techvault` in a filename.
- **Environment and secret binding:** `.env` remains parsed and shaped by the
  existing env helpers. Secrets, bearer tokens, cookies, rendered credentialized
  config, private keys, and generated SOC material must not be copied into SDL,
  manifests, workflow histories, diagnostics, or expected-output fixtures.
- **Deployment and OS exposure:** Docker Compose lifecycle and host/container
  inspection stay behind `DeploymentBackend`. Do not add raw `docker`, shell,
  or `curl` calls in orchestration code; SOC HTTP probes use `curl_safe`, and
  no secret-bearing value belongs in argv, URLs, logs, or command output.
- **Error envelopes and observability:** ACES-facing failures stay as ACES
  diagnostics or operation status details. APTL-facing failures stay in
  `LabResult`, `StartupDiagnostic`, `GateReport`, CLI/API schemas, or pytest
  assertions. Redaction happens before logs, API/CLI output, run archives, and
  generated reports.
- **Persistence and run archive:** workflow history, realization provenance,
  status snapshots, and validation observations are analysis artifacts, not
  credential stores. Write structured evidence through `LocalRunStore` or
  existing redacting boundaries; avoid archive keys such as `passed` that are
  redacted by the password heuristic.

## Extensibility Seam

The durable seam is `(scenario_path, backend_profile, target_name,
workflow_address)` plus the ACES capability declaration:
`supported_sections`, `supported_workflow_features`, and
`supported_workflow_state_predicates`. The next profile change should require
changing those inputs and capability sets, not editing TechVault-specific
branches or inventing a second manifest shape.

Keep provisioning realization content-driven and workflow interpretation
workflow-address-driven. Orchestration-capable must not close the door on #312:
evaluation results, objective scoring, and participant-runtime contracts remain
separate profile surfaces.

## Gotchas And Anti-Patterns

- Declaring `capabilities.orchestrator` or workflow contracts without a real
  orchestrator component and populated result/history payloads.
- Continuing the direct provisioning apply path after claiming
  `orchestration-capable`, or treating planner diagnostics for missing
  evaluation as an orchestration waiver.
- Reusing `src/aptl/core/runtime/*`, `src/aptl/backends/stubs.py`, or
  `ScenarioSession.completed_objectives` as the published ACES workflow result
  source of truth.
- Creating duplicate schemas, exception hierarchies, conformance scripts,
  run-archive models, health taxonomies, or validation report DTOs.
- Hardcoding TechVault, profile names, Compose profiles, workflow addresses, or
  scenario paths inside the orchestrator.
- Flattening `ApplyResult.details["realization"]`,
  `RuntimeSnapshot.orchestration_results`, or workflow history into lossy
  summaries before ACES contract validation.
- Treating evidence bundles, screenshots, logs, checksums, or mapping ledgers
  as substitutes for SDL expression or ACES blocker issues.
- Updating only CI while leaving pre-commit, static gate defaults, live gate
  profile checks, or unit tests on `provisioning-only`.

## Non-Goals

- Do not implement the orchestrator, manifest promotion, tests, CI changes,
  run archive writes, or public start-path changes in this preflight.
- Do not perform Phase B cutover, flip the default scenario, archive legacy
  `scenarios/*.yaml`, delete `aptl.core.sdl`, or delete Pydantic
  `ScenarioDefinition` models.
- Do not promote to orchestration-evaluation, implement objective scoring,
  publish evaluator contracts, or claim participant-runtime support; those are
  #312 or later.
- Do not redesign Docker Compose, config/env loading, secret handling, API
  schemas, terminal relay, endpoint registry, SOC TLS, or run archive layout.
- Do not treat APTL consumption gaps or filed ACES expressivity issues as
  waivers for SCN-010 observable parity.
