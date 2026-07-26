# DSL-008 RAES Topology Realization Preflight

!!! warning "Historical backend-profile milestone"
    This is a dated preflight record, kept as written. Where it names the
    captured `scenarios/techvault.sdl.yaml`, the SCN-010 parity inventory
    (`docs/raes/parity-inventory.yaml`), the parity-manifest gate check, the
    `aptl raes-inventory` command, or the per-asset mapping ledgers, it no
    longer describes the repository: all of them were removed in #690. The
    asset-inventory capture capability now lives in RAES; APTL keeps
    `scenarios/techvault-operational.sdl.yaml` as its only driving contract.
    See the Capture Inventory and Parity-Inventory Removal Addendum in
    [ADR-046](../adrs/adr-046-dynamic-raes-scenario-realization.md).
    Its `orchestration-evaluation` references also describe the profile at that
    milestone, not APTL's current `full-remote-control-plane` claim. See the
    current [backend manifest](techvault-static-validation-gate.md#backend-manifest).

This note is the architecture preflight for DSL-008 / issue #422. It is
guidance, not an implementation plan. ADR-035 remains the binding RAES SDL
adoption decision; this note narrows the backend realization guardrails for
RAES topology and runtime-model content.

## Architecture Decisions

- RAES remains the scenario and topology authority. APTL consumes RAES parser,
  compiler, planner, and contract output; it must not structurally revalidate
  RAES SDL through `aptl.core.sdl`, `aptl.core.scenarios`, or a new local
  Pydantic scenario model.
- The implementation must extend the existing APTL RAES adapter seams:
  `aptl.backends.raes`, `raes_realization`, `raes_realization_model`,
  `raes_realization_values`, `raes_profiles`, `raes_dependency_closure`, and
  `raes_diagnostics`. Do not add a parallel backend interpreter.
- Docker Compose remains a backend capability graph, not scenario meaning.
  RAES resources map to Compose services, profiles, networks, static
  addresses, volumes, and health only through model-derived realization data
  and the existing Compose profile/dependency index.
- Before workflow or scenario execution proceeds, APTL must prove that the
  planned/running lab satisfies the RAES declarations it claims to realize. A
  live proof must use `DeploymentBackend` inventory and snapshot/readiness
  owners, not raw Docker subprocesses or the live validation gate as the only
  enforcement point.
- Supported topology changes must be driven by RAES plan operations and an
  explicit support matrix. If the existing backend methods cannot faithfully
  express a transition, return RAES diagnostics instead of shelling out to an
  ad hoc Docker command.
- Failure surfaces stay existing and layered: RAES-facing failures are
  `raes_contracts.diagnostics.Diagnostic` records and operation statuses;
  APTL-facing failures are `LabResult`, `StartupDiagnostic`, gate reports,
  CLI/API schemas, and tests. Do not add an `AcesAptlError` hierarchy.

## Cross-Cutting Concerns To Reuse

- RAES authorities: `raes.parse_sdl_file`, RAES semantic validation,
  `RuntimeManager.plan()`, `RuntimeControlPlane`, `ProvisioningPlan`,
  `RuntimeSnapshot`, `ApplyResult`, `ChangeAction`, backend manifest v2, and
  conformance against the current `orchestration-evaluation` profile.
- APTL RAES adapter: `create_aptl_runtime_target()`, `AptlProvisioner`,
  `AptlOrchestrator`, `AptlEvaluator`, `interpret_provisioning_plan()`,
  `AptlRealization.details()`, `select_backend_profiles()`, and
  `render_raes_diagnostics()`.
- Compose/deployment owners: `docker-compose.yml`, `DeploymentBackend`,
  `DockerComposeBackend`, `SSHComposeBackend`, `ComposeQueryMixin`,
  project-name scoping, compose-project label filters, backend timeouts, and
  argv-list subprocess construction.
- Config/env owners: strict `AptlConfig`, `ContainerSettings.enabled_profiles()`,
  `DeploymentConfig`, `load_config()`, `load_dotenv()`, `EnvVars`,
  `env_vars_from_dict()`, and `find_placeholder_env_values()`.
- Lab lifecycle owners: `orchestrate_lab_start()`, `_LAB_START_STEPS`,
  generated credential config, Suricata volume seeding, SOC TLS generation,
  bind-mount checks, service waits, SSH probes, host-key pinning, snapshots,
  MCP build/config refresh, `LabResult`, `StartupOutcome`, and
  `StartupDiagnostic`.
- Runtime inventory and evidence owners: `capture_snapshot()`,
  `RangeSnapshot.to_dict()`, `ContainerSnapshot`, `NetworkSnapshot`,
  `container_networks()`, `list_container_snapshots()`, endpoint registry
  projection, `LocalRunStore`, collectors, and live/static RAES gates.
- Shared security helpers: ADR-025, ADR-028, ADR-029, ADR-030, ADR-031,
  ADR-034, ADR-036, ADR-037, ADR-039, ADR-040, `redact()`, `curl_safe`, and
  `get_logger()`.
- Workflow and repo gates: `.pre-commit-config.yaml`, `.github/workflows/checks.yml`,
  `pyproject.toml`, `uv.lock`, `pytest`, the manual RAES scenario gate,
  `scenarios/catalog.json`, `scenarios/techvault-operational.sdl.yaml`,
  `scenarios/techvault.sdl.yaml`, and `docs/raes/parity-inventory.yaml`.

## Security And Validation Layers

- **RAES SDL shape:** parser, import-lock, semantic validation, runtime
  compiler, planner, and planner diagnostics are the first gate. APTL may
  interpret planned resources, but not parse local RAES-shaped YAML itself.
- **Plan and manifest shape:** `RuntimeManager.plan()` diagnostics fail closed
  before backend changes. The manifest must remain the canonical RAES
  `backend-manifest-v2`; older prose that names prior profiles is historical,
  while current code and gates use `orchestration-evaluation`.
- **Config shape:** durable non-secret knobs stay in strict `AptlConfig`.
  Profile enablement comes from `ContainerSettings.enabled_profiles()` plus the
  core `otel` profile logic, not hardcoded TechVault lists or unchecked
  `aptl.json` dictionaries.
- **Environment binding:** `.env` is parsed and shaped by the existing env
  helpers, with placeholder rejection before generated config. RAES topology
  diagnostics may name variable names, profile names, service names, and
  resource addresses, but never `.env` values.
- **Generated artifacts:** rendered Wazuh config, lab CA material, SSH keys,
  and named-volume seeds stay owned by existing startup steps and ADR-028 /
  ADR-034 / ADR-043 boundaries. Do not turn generated secret-bearing config
  into RAES content or realization details.
- **Deployment and OS exposure:** all Docker lifecycle, container, network,
  log, and inspect operations go through `DeploymentBackend`. Do not pass
  tokens, cookies, passwords, private keys, generated config values, or raw
  secret-bearing command strings through process argv, logs, or diagnostics.
- **Live topology proof:** compare RAES realization to backend/snapshot data
  for container presence, Compose service/profile selection, network
  attachment, static address, declared volume/mount support, and health where
  RAES declares it. Serialize any proof through existing redaction boundaries.
- **Error envelopes:** RAES diagnostics should carry stable codes and resource
  addresses. CLI/API/web projections should continue through `LabResult`,
  `StartupOutcome`, `StartupDiagnostic`, and `LabActionResponse`; do not
  reclassify failures by scraping English text.
- **Persistence and observability:** run artifacts, live-gate manifests,
  snapshots, traces, and reports are analysis artifacts. Structured writes use
  `LocalRunStore` redacting JSON/JSONL paths or `RangeSnapshot.to_dict()`;
  opaque file copies are not a first redaction point.

## Extensibility Seam

The durable seam is `(scenario_path, backend_profile, project_dir,
project_name, RAES resource address, RAES resource type, ChangeAction)` plus a
small support map from RAES runtime/provisioning resource kinds to existing
APTL owners.

New declared surfaces should extend the realization value objects and field
extractors first, then reuse the same comparison and diagnostic path. Examples:
volumes/mounts belong as realized node/runtime fields; health belongs as a
declaration compared to Compose/snapshot readiness; new topology transitions
belong in a `ChangeAction` support matrix. The next supported scenario should
change inputs, not require a TechVault branch.

If a future provider needs different mechanics, the provider seam is
`DeploymentBackend`. Do not leak Docker-CLI details into RAES adapter code as a
shortcut around that protocol.

## Gotchas And Anti-Patterns

- Dispatching on scenario name, file path, `techvault`, metadata, or a preset
  flag instead of RAES resource content.
- Reintroducing an APTL-local scenario DSL, local RAES schema mirror, duplicate
  Compose parser, duplicate validation report DTO, duplicate readiness
  taxonomy, duplicate redaction helper, or duplicate exception hierarchy.
- Silently dropping RAES-declared nodes or services whose profiles are disabled
  in `aptl.json`. Required but disabled or unsupported declarations need
  explicit diagnostics before execution.
- Treating a successful `docker compose up` as proof that the running lab
  satisfies RAES declarations. Runtime validation must check declared networks,
  addresses, services, health, and supported mounts/volumes.
- Treating `docs/raes/parity-inventory.yaml`, evidence bundles, or mapping
  ledgers as runtime inputs. They are audit/evidence surfaces.
- Adding raw `docker`, `docker compose`, `docker inspect`, `docker logs`, or
  `curl` calls in RAES realization or validation code.
- Flattening `ApplyResult.details["realization"]` until RAES resource
  addresses, resource types, and unsupported-declaration diagnostics are lost.
- Modeling generated service config, operator API keys, private SSH/TLS keys,
  cookies, bearer tokens, or rendered `.env` values as RAES topology content.
- Making partial delete/update transitions destructive by accident. If
  `DeploymentBackend.start()` / `stop()` cannot express the exact operation,
  fail closed with an unsupported-transition diagnostic.
- Copying stale profile names from older preflight prose instead of using the
  current manifest/gate default and conformance target.

## Non-Goals

- Do not implement DSL-008 in this preflight.
- This preflight did not perform the later ADR-035 cutover cleanup; legacy
  parser removal, scenario archival, and public default selection were handled
  by follow-on work.
- Do not redesign Docker Compose, `DeploymentBackend`, lab startup ordering,
  generated config, SOC TLS, endpoint registry, API/web schemas, terminal
  relay, run archive layout, or collector transport.
- Do not add Kubernetes, Podman, Nomad, or participant-runtime support.
- Do not make every RAES topology transition supported in Wave 1. Unsupported
  transitions are valid only when they fail explicitly with RAES diagnostics.
- Do not treat live validation gates as substitutes for runtime guardrails.
