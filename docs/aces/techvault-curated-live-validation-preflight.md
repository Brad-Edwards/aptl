# TechVault curated live validation preflight

This note is the architecture preflight for issue #535. It is guidance, not an
implementation plan. The full TechVault live gate remains documented separately
in [TechVault live validation gate](techvault-live-validation-gate.md); this
work proves the small catalog variants from
[`docs/sdl/techvault-curated-variants.md`](../sdl/techvault-curated-variants.md)
against their reduced live surface.

## Architecture decisions

- The proof must enter through the public startup path: catalog resolution via
  `resolve_scenario_selection()`, then `orchestrate_lab_start()` /
  `_step_start_containers()` / `start_aces_scenario()`. A direct
  `AptlProvisioner.apply()` call is acceptable only for static expectations,
  never as live boot proof.
- The expected live surface is model-derived and reduced. Compute it from ACES
  parse/compile/plan/realization, `selected_profiles_for_scenario()`,
  `select_backend_profiles()`, `load_compose_profile_index()`, and the captured
  `RangeSnapshot`. Do not compare a curated variant to the full TechVault
  legacy container or network set.
- Passing proof means the post-boot containers and networks match the
  ACES-realized selected Compose profile set. Because Compose activates every
  service in a selected profile, expected containers are the steady-state
  services selected by those profiles, not only the declared ACES nodes.
- Readiness must reuse `LabResult`, `StartupOutcome`, `StartupDiagnostic`, and
  the live-gate failure categories. Variants that intentionally omit Kali, Wazuh,
  or SOC must not fail a full-surface probe merely because that profile is not
  in the selected reduced surface.
- Evidence belongs in run archives or in a documented local evidence path using
  the existing redacting boundaries. Prefer `LocalRunStore.write_json()` /
  `write_jsonl()` / `append_jsonl()` for structured proof artifacts. If a
  variant matrix needs a new artifact, make it a thin wrapper around the live
  gate manifest shape rather than a second run archive schema.
- Proof docs must record exact ISO dates, commands, scenario catalog ids,
  selected profiles, realized node names, container count/names, network
  count/names, readiness outcome, pass/fail, run id or evidence path, and any
  linked follow-up issue for a statically valid but not live-runnable variant.

## Cross-cutting concerns to reuse

- Scenario authority: `scenarios/catalog.json`, `aptl.core.scenario_catalog`,
  `aces_sdl.parse_sdl_file`, ACES import/compile/planning diagnostics, and
  `RuntimeManager.plan()`.
- Realization and profile authority: `aptl.backends.aces_realization`,
  `aptl.backends.aces_dependency_closure`, `aptl.backends.aces_profiles`,
  `selected_profiles_for_scenario()`, `public_start_profiles()`, and
  `ComposeProfileIndex.cross_profile_dependency_gaps()`.
- Startup authority: `orchestrate_lab_start()`, `_LAB_START_STEPS`,
  `_LabStartContext.selected_profiles`, `start_aces_scenario()`, `stop_lab()`,
  `LabResult`, `StartupOutcome`, and `StartupDiagnostic`.
- Deployment and runtime inventory: `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, `capture_snapshot()`, `RangeSnapshot.to_dict()`,
  `container_networks()`, `list_container_snapshots()`, and the endpoint
  registry.
- Config/env/generated artifact owners: `AptlConfig`, `ContainerSettings`,
  `load_config()`, `load_dotenv()`, `env_vars_from_dict()`,
  `find_placeholder_env_values()`, `sync_dashboard_config()`,
  `sync_manager_config()`, `ensure_ssl_certs()`, `ensure_soc_certs()`,
  Suricata volume seeding, and `_check_bind_mounts()`.
- Evidence and diagnostics: `LiveGateReport`, `LiveGateCheck`,
  `_live_gate_checks`, `_live_gate_probes`, `LocalRunStore`, `resolve_run_store()`,
  `aptl.utils.redaction.redact()`, `aptl.utils.logging.get_logger()`, and
  `curl_safe` for SOC HTTP probes.

## Security and validation layers

- **Catalog and path containment:** selected variants must pass
  `resolve_scenario_selection()`, project containment, catalog schema validation,
  and ACES parser validation. Do not add a scenario-name switch or path
  allowlist outside the catalog/explicit-path resolver.
- **ACES shape and backend contracts:** parse, compile, plan, realization,
  backend manifest, and profile conformance stay ACES-owned. APTL proof code
  must not create a local Pydantic mirror of ACES SDL or flatten away ACES
  resource addresses from realization evidence.
- **Config shape:** durable non-secret knobs stay in strict `AptlConfig` and
  `ContainerSettings.enabled_profiles()`. The proof must not add unchecked
  `aptl.json` dictionaries for expected containers, networks, probes, or
  scenario presets.
- **Environment binding:** `.env` still flows through `load_dotenv()`,
  `env_vars_from_dict()`, and placeholder rejection before startup. Do not relax
  required env validation inside proof code; if the public startup path requires
  broad env values for a small variant, document it as a current startup
  prerequisite or file a follow-up for profile-scoped startup prerequisites.
- **Generated artifacts and TLS:** credentialized Wazuh config, Suricata runtime
  volume seeds, SSL certs, and SOC CA material must be generated through the
  existing startup steps. Do not write rendered config, private keys, API keys,
  or token values into proof docs or manifests.
- **Deployment boundary:** all Docker lifecycle, container, log, and network
  inspection must go through `DeploymentBackend`. Do not add raw `docker`,
  `docker compose`, or daemon-wide inspection subprocesses in proof logic.
- **OS/process exposure:** proof commands may include catalog ids, scenario
  paths, and run ids, but not passwords, bearer tokens, cookies, private keys, or
  generated config values. Use argv-list backend calls and `curl_safe` where
  credentials are involved.
- **Error envelopes and logging:** expected failures should become
  `LiveGateCheck` / `LiveGateReport` diagnostics, `LabResult` diagnostics, or
  pytest assertions. Messages may name the failed layer, scenario id, profile,
  container, network, or missing dependency, but must be redacted before logs,
  CLI/API output, telemetry, or persistence.
- **Persistence:** run ids and paths must pass `LocalRunStore` validation.
  Structured artifacts must use the redacting write paths; `write_file()` /
  `copy_file()` are inappropriate for proof data that can contain control-plane
  secrets.
- **Host/network exposure:** proving a variant must not change Docker published
  ports, web API auth, terminal SSH host-key verification, or network
  segmentation. If the proof touches API or terminal paths, ADR-039 and ADR-040
  still apply.

## Extensibility seam

The seam is `(catalog_id, scenario_path, run_id, selected_profiles,
realization_details)` plus a model-derived expected live matrix keyed by ACES
resource addresses, Compose service aliases, and selected-profile networks. The
next curated variant should require adding catalog/scenario data and expected
documentation, not editing a TechVault-name branch or a hardcoded container
table.

If expected network calculation needs more structure than
`load_compose_profile_index()` exposes today, extend `aptl.backends.aces_profiles`
with a small selected-profile helper. Do not parse `docker-compose.yml` again in
validation, docs tooling, CLI, or tests.

## Gotchas and anti-patterns

- Treating `config.containers.enabled_profiles()` as the expected live surface.
  Curated scenarios can start a subset; use `selected_profiles_for_scenario()`
  and the live snapshot.
- Running Kali reachability or telemetry-generation checks against variants that
  do not select `kali` and a reachable target. Record the absence as outside the
  reduced surface, not as an ambiguous startup failure.
- Counting one-shot or seed containers as steady-state proof containers.
  Compare steady-state services selected by the active profiles to the snapshot.
- Creating a second profile map, catalog schema, Docker parser, readiness DTO,
  failure taxonomy, redaction helper, or exception hierarchy.
- Scraping human `docker compose` errors, CLI text, or logs to decide pass/fail
  when ACES diagnostics, `LabResult`, `StartupDiagnostic`, `RangeSnapshot`, and
  backend methods already expose structured data.
- Weakening `.env`, generated artifact, bind-mount, SOC TLS, or SSH-remote
  deployment safeguards to make a small variant easier to boot.
- Letting the curated proof replace or rewrite the full TechVault live gate.
  The PR #520 full-surface proof remains a separate validation artifact.
- Publishing relative dates such as "today" or "latest run" in proof docs.
  Use exact dates and exact commands.

## Non-goals

- Do not implement the curated live proof, run Docker, add scenario files, or
  change startup behavior in this preflight.
- Do not change the default public scenario, full TechVault live gate, static
  gate, parity inventory, ACES backend profile claim, or Docker Compose profile
  topology.
- Do not redesign run archive layout, deployment backends, endpoint registry,
  startup readiness classification, generated config, SOC TLS, web auth, or
  terminal host-key verification.
- Do not make live variant proof part of fast CI or pre-commit. It is a
  destructive/manual or explicitly gated integration activity.
