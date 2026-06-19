# TechVault ACES Live Validation Preflight

This note is the architecture preflight for SCN-010F / issue #323. It is
guidance, not an implementation plan. ADR-035 remains the binding ACES adoption
decision, and the static gate in `aptl.validation.techvault_gate` remains the
pre-live prerequisite.

## Architecture Decisions

- The live gate must exercise the public lab lifecycle path:
  `aptl lab stop -v` cleanup followed by `aptl lab start`. It may call the
  Python core entrypoints for testability, but the behavior under test is
  `orchestrate_lab_start()`, `_LAB_START_STEPS`, and the ACES handoff inside
  `_step_start_containers()`, not a direct `AptlProvisioner.apply()` shortcut.
- ACES remains the scenario authority. The gate must enter through the ACES
  reference parser, `RuntimeManager.plan()`, APTL's `RuntimeTarget`, and the
  `AptlProvisioner` realization path. It must not inspect the scenario name or
  path and then select a TechVault preset.
- Concrete realization evidence must come from the ACES runtime/backend
  artifacts already produced by the adapter: the backend manifest/profile,
  `ExecutionPlan.provisioning`, ACES diagnostics, and
  `ApplyResult.details["realization"]`. Expected services, networks, rendered
  config hints, placements, and profile selections should be tied to ACES
  resource addresses and realization details, not a hardcoded service list.
- Runtime/lab readiness must reuse APTL's lifecycle DTOs:
  `LabResult`, `StartupOutcome`, `StartupDiagnostic`, and the existing
  readiness helpers. Do not create a second health taxonomy for live
  validation.
- Live Docker, host, container, log, and network inspection must go through
  `DeploymentBackend`. The gate may use backend methods such as
  `container_exec()`, `container_logs_capture()`, `container_inspect()`,
  `host_list_lab_containers()`, and `host_inspect_network()`, but not raw
  Docker subprocess calls in validation code.
- Run evidence belongs in the existing run archive boundary. New structured
  evidence should use `LocalRunStore.write_json()`, `write_jsonl()`, or
  `append_jsonl()` so ADR-029 redaction applies before persistence. Opaque
  `write_file()` / `copy_file()` are only acceptable for deliberately
  classified target evidence whose raw form is required and reviewed.
- Failure output must identify the failing layer with stable categories:
  ACES specification, backend interpretation, backend instantiation, defensive
  stack readiness, Kali reachability, or evidence/run archive capture. Map
  those categories onto existing ACES diagnostics and APTL startup diagnostics;
  do not introduce a parallel exception hierarchy.
- The gate is inherently integration/live-run work. It should be marked and
  wired as an explicit live or manual gate with documented runner
  prerequisites rather than hidden in fast unit tests or silently skipped when
  Docker/SOC prerequisites are absent.

## Cross-Cutting Concerns To Reuse

- ACES authorities: `aces_sdl.parse_sdl_file`, `aces sdl verify-imports`,
  `aces_processor.compiler.compile_scenario_runtime_model`,
  `aces_runtime.manager.RuntimeManager`, ACES `Diagnostic` records, and
  `aces conformance backend --profile provisioning-only`.
- Backend contract authorities: `create_aptl_manifest()`,
  `backend-manifest-v2`, `contracts/profiles/backend/provisioning-only.json`,
  `operation-receipt-v1`, `operation-status-v1`, and `runtime-snapshot-v1`.
- APTL ACES adapter seams: `src/aptl/backends/aces.py`,
  `src/aptl/backends/aces_realization.py`,
  `src/aptl/backends/aces_realization_model.py`,
  `src/aptl/backends/aces_realization_values.py`,
  `src/aptl/backends/aces_profiles.py`, and
  `src/aptl/backends/aces_diagnostics.py`.
- Static and parity gates: `src/aptl/validation/techvault_gate.py`,
  `src/aptl/validation/_gate_checks.py`, `docs/aces/parity-inventory.yaml`,
  and existing inventory tests. Static parse/compile/conformance/parity
  failures block the live gate rather than becoming live-gate warnings.
- Lab lifecycle owners: `orchestrate_lab_start()`, `stop_lab()`,
  `_LAB_START_STEPS`, `_LabStartContext`, `LabResult`, `StartupOutcome`, and
  `StartupDiagnostic`.
- Config and environment owners: `AptlConfig`, `ContainerSettings`,
  `DeploymentConfig`, `load_config()`, `load_dotenv()`, `EnvVars`,
  `env_vars_from_dict()`, and `find_placeholder_env_values()`.
- Generated artifact owners: `sync_dashboard_config()`,
  `sync_manager_config()`, `sync_suricata_misp_rule_baselines()`,
  `ensure_ssl_certs()`, `ensure_soc_certs()`, and `_check_bind_mounts()`.
- Deployment and runtime inventory: `DeploymentBackend`,
  `DockerComposeBackend`, `SSHComposeBackend`, `capture_snapshot()`,
  `RangeSnapshot.to_dict()`, `container_networks()`, `list_container_snapshots()`,
  and `ENDPOINT_REGISTRY`.
- Evidence collectors and transport safety: `collect_wazuh_alerts()`,
  `collect_suricata_eve()`, `collect_thehive_cases()`, `collect_misp_events()`,
  `collect_shuffle_executions()`, `collect_container_logs()`,
  `collect_traces()`, and `curl_safe.curl_json()`.
- Persistence and user surfaces: `LocalRunStore`, `resolve_run_store()`,
  `docs/reference/experiment-runs.md`, `aptl lab status --json`,
  `aptl runs *`, API `LabActionResponse`, and CLI lab result rendering.
- Shared safety helpers and policy: ADR-025, ADR-028, ADR-029, ADR-030,
  ADR-031, ADR-034, ADR-036, ADR-037, ADR-039, ADR-040,
  `aptl.utils.redaction.redact()`, and `aptl.utils.logging.get_logger()`.
- Repo workflow gates: `.pre-commit-config.yaml`, `.github/workflows/checks.yml`,
  `pyproject.toml`, `pytest`, integration markers, and
  `pre-commit run --all-files`.

## Security And Validation Layers

- **ACES SDL shape:** the scenario must pass ACES parser, import-lock,
  semantic validation, runtime compilation, planning, and manager provenance
  checks. APTL must not add a local Pydantic mirror or direct
  `ScenarioDefinition` compatibility path for live validation.
- **Import and dependency trust:** ACES module resolution and
  `aces.lock.json` verification are ACES-owned. Do not fetch, expand, or
  execute imports through an APTL helper.
- **Backend manifest/profile:** the live gate must use APTL's real
  `RuntimeTarget` manifest and the canonical `provisioning-only` profile.
  Missing ACES profile, fixture, CLI, or contract assets are actionable
  failures, not waivers.
- **Config shape:** durable knobs stay in strict `AptlConfig`; the live gate
  must not add pass-through dictionaries, scenario-name flags, or unchecked
  `aptl.json` sections for expected services or probe behavior.
- **Environment binding:** `.env` remains parsed by `load_dotenv()`, shaped by
  `EnvVars`, and placeholder-checked before startup. Control-plane secrets
  must not be copied into SDL, expected-output fixtures, run manifests, or
  diagnostics.
- **Generated config and TLS:** credentialized Wazuh config, Suricata MISP
  rule baselines, SSL certs, and SOC CA material must be materialized through
  existing startup steps before bind-mount validation. Private keys, rendered
  secret-bearing config, and API tokens stay out of snapshots and archives
  except as redacted data or hashes.
- **Deployment boundary:** Docker Compose lifecycle and host/container
  inspection remain behind `DeploymentBackend`, preserving local and
  SSH-compose behavior, compose-project scoping, timeouts, and result
  envelopes. Use argv-list subprocess construction only inside existing
  backend or collector boundaries.
- **OS/process exposure:** do not place bearer tokens, API keys, passwords,
  cookies, private keys, or generated config values in process argv, shell
  strings, URLs, or command output. SOC HTTP probes use `curl_safe`; backend
  container probes use `container_exec()` with bounded timeouts and no
  control-plane secrets in arguments.
- **Network exposure:** the gate must not weaken loopback-only host publishes
  or terminal SSH host-key verification. If it exercises the web API or
  terminal relay, it must satisfy ADR-039 auth and ADR-040 endpoint/trust
  boundaries instead of bypassing them for test convenience.
- **Error envelopes and logging:** ACES-facing failures stay as ACES
  diagnostics or operation status details. APTL-facing failures stay in
  `LabResult`, `StartupDiagnostic`, `GateReport`, CLI/API schemas, or pytest
  assertions. Every message crossing logs, CLI, API, telemetry, or persistence
  uses `redact()` or an existing redacting boundary.
- **Persistence:** run evidence and live-gate reports are analysis artifacts,
  not credential stores. Store structured ACES provenance, realization details,
  snapshot data, collector summaries, and validation observations through
  `LocalRunStore` redacting writes; export packaging must not be the first
  redaction point.

## Extensibility Seam

The seam is the tuple `(scenario_path, backend_profile, target_name,
project_dir, run_id)` plus a model-derived validation matrix keyed by ACES
runtime resource addresses, realization details, and endpoint registry entries.
The next scenario in APTL's supported expressivity class should reuse the same
gate by changing those inputs.

Add a new probe only when a new ACES runtime resource kind or APTL-supported
service family needs a reusable evidence collector. Do not add branches for
`techvault`, file paths, scenario names, or Compose profile presets. Scenario
variation proof for #324 should compare two declared ACES inputs and their
distinct realization details through the same interpreter path.

## Gotchas And Anti-Patterns

- Calling `docker compose`, `docker inspect`, `docker logs`, or `curl` directly
  from live-gate code when an existing backend, collector, or `curl_safe`
  helper owns that concern.
- Treating the historical smoke-test plan's raw commands as implementation
  patterns. It is a catalog of expected surfaces, not the executable
  architecture boundary.
- Selecting profiles from `techvault` in the scenario name, path, metadata, or
  `lab.name` instead of from ACES provisioning resources and realization hints.
- Copying `ApplyResult.details["realization"]` into a second schema or losing
  its ACES resource addresses in a flattened report.
- Creating new DTOs for readiness, health, run archives, endpoint inventory,
  Docker rows, conformance reports, or failures when existing DTOs already
  cover the boundary.
- Classifying missing conformance assets, stale imports, missing `.env`
  values, placeholder secrets, or failed generated artifact materialization as
  live readiness warnings. Those are hard setup or contract failures.
- Archiving evidence bundles, logs, checksums, or screenshots as a substitute
  for SDL observable parity. Evidence proves what the SDL and backend realized;
  it does not replace SDL encoding or ACES blocker issues.
- Letting destructive cleanup (`stop -v`) run against an ambiguous project or
  shared Docker daemon. The runner must be isolated, scoped by project name,
  and documented as data-destroying.
- Adding a live gate to default fast CI or pre-commit in a way that requires
  Docker, 24GB-plus memory, SOC secrets, or minutes-long startup for ordinary
  Python edits. Use explicit integration/live-run wiring.

## Non-Goals

- Do not implement the live gate, probes, run archive writers, CI wiring, or
  documentation of operator commands in this preflight.
- Do not perform Phase B cutover, flip the default scenario, move legacy
  `scenarios/*.yaml` to `scenarios/archive/`, delete `aptl.core.sdl`, or delete
  Pydantic scenario models.
- Do not promote APTL beyond `provisioning-only`; #311 and #312 own
  orchestration/evaluation profile upgrades.
- Do not redesign Docker Compose, generated service config, endpoint registry,
  terminal relay, web auth, SOC TLS, run archive layout, or deployment
  backends.
- Do not treat filed ACES expressivity issues as waivers. They block final
  SCN-010 parity until the SDL can encode the observable surface and validation
  passes.
