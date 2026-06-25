# RNG-001 Ephemeral Environments Preflight

This note is the architecture preflight for RNG-001 / issue #424. It is
guidance, not an implementation plan. Existing ADRs remain binding: ADR-013
and ADR-023 own deployment backends, ADR-025 owns first-party config shape,
ADR-028 owns runtime-rendered config, ADR-029 owns secret handling, ADR-030
owns lab-result envelopes, ADR-031 owns orchestration contract guards, and
ADR-037 owns Docker Compose backend cohesion.

## Architecture Decisions

- Treat "ephemeral environment" as a destructive lab lifecycle mode:
  stop the selected lab deployment with volume removal, then boot through the
  public start path. The behavior under test is the same core lifecycle used by
  `aptl lab start`, `aptl lab stop -v`, and the ACES live gate, not a new
  Docker script.
- Clean state means removing runtime contamination from containers, processes,
  Compose-managed volumes, service databases, service logs, and generated
  in-container credentials. It does not mean deleting source inputs, `.env`,
  run archives, ACES inventory evidence, local SSH keys, or checked-in config
  unless a future requirement explicitly adds a separate purge surface.
- Keep clean boot project-scoped. Cleanup must target the configured
  `deployment.project_name` and selected profiles through `DeploymentBackend`;
  it must not enumerate or remove unrelated Docker containers, networks, or
  volumes on a shared daemon.
- Reuse the existing startup pipeline after cleanup:
  `orchestrate_lab_start()`, `_LAB_START_STEPS`, the ACES handoff in
  `_step_start_containers()`, generated config renderers, Suricata volume
  seeding, bind-mount checks, SOC seeding, MCP config sync, and snapshot
  capture.
- Do not make the live validation gate the only clean-state implementation.
  `aptl lab validate-live` already proves the destructive sequence, but
  RNG-001 should expose a reusable lifecycle capability that validation can
  continue to consume.

## Cross-Cutting Concerns To Reuse

- Lab lifecycle: `orchestrate_lab_start()`, `stop_lab(remove_volumes=True)`,
  `_LabStartContext`, `_LAB_START_STEPS`, `LabResult`, `StartupOutcome`, and
  `StartupDiagnostic`.
- Deployment boundary: `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, project-name scoping, compose-project labels, backend
  timeouts, `BackendTimeoutError`, and `BackendSeedError`.
- Config and environment: `AptlConfig`, `DeploymentConfig`,
  `ContainerSettings.enabled_profiles()`, `load_config()`, `load_dotenv()`,
  `EnvVars`, `env_vars_from_dict()`, and `find_placeholder_env_values()`.
- Generated artifacts: `sync_dashboard_config()`, `sync_manager_config()`,
  `build_suricata_volume_seeds()`, `ensure_ssl_certs()`, `ensure_soc_certs()`,
  `_check_bind_mounts()`, and `scripts/seed-prime.sh`.
- API and web surfaces: `LabActionResponse`, `StartupDiagnosticModel`,
  `StartupOutcomeLiteral`, `web/src/lib/types.ts`, and the existing API auth
  dependency chain in `aptl.api.deps`.
- Observability and persistence: `get_logger()`, `redact()`,
  `RangeSnapshot.to_dict()`, `LocalRunStore.write_json()` /
  `write_jsonl()` / `append_jsonl()`, and existing run archive docs.
- Existing destructive proof point: `_live_gate_probes._boot_lab()` and
  `LiveGateOptions.clean_volumes` / `skip_clean_boot`.

## Security And Validation Layers

- **Auth surface:** any API or web trigger for clean boot must remain behind
  ADR-039 bearer-token auth. Do not pass destructive-mode intent, API tokens,
  or control-plane secrets in query strings, WebSocket subprotocols, logs, or
  EventSource URLs.
- **Environment binding:** `.env` continues to flow through `load_dotenv()`,
  `env_vars_from_dict()`, `EnvVars`, and placeholder rejection before generated
  config or service probes consume it. Clean boot must not parse `.env` again in
  a second helper.
- **Config shape:** durable knobs belong in strict `AptlConfig` /
  `DeploymentConfig` with `extra="forbid"`. Transient CLI/API options may exist
  at the public boundary, but do not add unchecked dictionaries, duplicate
  profile lists, or a second clean-state schema.
- **Deployment boundary:** cleanup and boot go through `DeploymentBackend`.
  Docker Compose implementations must preserve `-p <project_name>`,
  compose-project label filters, SSH transport semantics, timeout translation,
  and argv-list subprocess construction.
- **Generated-artifact boundary:** clean boot must re-run the existing render
  and seed steps. Do not reuse stale `.aptl/config/...`, Suricata named-volume
  contents, SOC certs, or SOC API key wiring as proof of clean state. Existing
  SSH-remote generated-artifact refusals remain valid until backend-owned
  remote materialization exists.
- **OS/process exposure:** no bearer tokens, passwords, API keys, private keys,
  raw `.env` values, or command lines with credentials may appear in argv,
  shell strings, diagnostics, or logs. Preserve argv-list subprocess calls and
  avoid `shell=True`.
- **Error envelopes:** return existing `LabResult` / `LabActionResponse`
  shapes. A failed cleanup is a fatal lifecycle failure, not a new exception
  hierarchy or a partial-readiness category. Redact raw Docker stderr before it
  crosses CLI, API, web, telemetry, or persistence.
- **Persistence boundary:** clean boot may write new snapshots, diagnostics,
  or run evidence through existing redacting runstore methods. It must not
  delete run archives or inventory bundles as part of the clean-state guarantee
  unless a separate purge feature explicitly owns that risk.

## Extensibility Seam

The seam belongs at the public lab lifecycle boundary as one destructive clean
boot mode carrying the existing inputs: project directory, scenario selection,
seed behavior, and a cleanup policy whose first implementation is volume
removal. Future variations, such as preserving run archives, selecting a
scenario catalog entry, or implementing non-Docker cleanup semantics, should
extend that single lifecycle mode or the backend's typed cleanup behavior
rather than re-editing validation, CLI, API, and test code independently.

## Whole-Repo Surface

- `aptl.json`, `.env`, `.env.example`, and `DeploymentConfig.project_name`.
- `docker-compose.yml`, top-level volumes, profiles, generated bind mounts,
  and Compose project labels.
- `.aptl/config/...`, `config/soc_certs/...`, `config/suricata/...`, `keys/`,
  and `.mcp.json`.
- `src/aptl/core/lab.py`, `src/aptl/core/deployment/`,
  `src/aptl/validation/_live_gate_probes.py`, `src/aptl/cli/lab.py`,
  `src/aptl/api/routers/lab.py`, `src/aptl/api/schemas.py`, and
  `web/src/lib/types.ts`.
- `src/aptl/core/runstore.py`, `src/aptl/core/snapshot.py`, collectors,
  `docs/reference/experiment-runs.md`, and live-gate evidence reports.
- Host Docker daemon state: containers, networks, named volumes, image cache,
  subprocess argv, and logs.
- Repo workflow gates: `.gc/plan-rules.md`, `pytest`, and
  `pre-commit run --all-files`.

## Gotchas And Anti-Patterns

- Calling `docker compose down -v`, `docker volume rm`, `docker ps`, or
  `docker network rm` directly from CLI, API, web, validation, or tests when a
  backend method already owns Docker access.
- Treating clean state as only "container restart" while preserving service
  volumes, SOC databases, generated rule volumes, or stale API-key sync state.
- Deleting broad host paths, run archives, `.env`, `.mcp.json`, `keys/`, or
  checked-in config as part of the default guarantee.
- Adding a `clean_state` section to `aptl.json` for behavior that is really an
  invocation-time choice.
- Inferring destructive behavior from scenario names, folders, issue IDs,
  config `lab.name`, or ACES metadata.
- Adding a new readiness taxonomy, exception hierarchy, Docker row DTO, or web
  response model when existing lifecycle and API envelopes already cover it.
- Logging raw Docker stderr, raw exception payloads, rendered config, or `.env`
  values to explain cleanup failures.
- Weakening remote deployment safety by pretending local generated artifacts
  are visible to an SSH remote Docker daemon.

## Non-Goals

- Do not implement RNG-001 in this preflight.
- Do not redesign Docker Compose, deployment backends, ACES realization,
  run archive layout, SOC seeding, Suricata rule semantics, or web
  authentication.
- Do not add Kubernetes, Podman, Nomad, or cloud cleanup semantics here.
- Do not guarantee byte-identical regenerated credentials, logs, timestamps,
  Docker object IDs, network IDs, endpoint IDs, or image cache contents across
  runs.
- Do not make destructive clean boot part of default fast CI or pre-commit.
