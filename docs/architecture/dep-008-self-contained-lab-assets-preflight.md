# DEP-008 Self-Contained Lab Assets Preflight

This note is the architecture preflight for DEP-008 / issue #659. It is
guidance, not an implementation plan. Existing ADRs remain binding: ADR-007
owns the Python CLI control plane, ADR-013/ADR-023/ADR-037 own deployment
backends, ADR-025 owns `aptl.json`, ADR-028 owns generated runtime config,
ADR-029 owns secret handling, ADR-030 owns lab result envelopes, ADR-031 owns
orchestration contracts, ADR-043 owns Suricata runtime seeding, and ADR-046
owns dynamic ACES realization.

## Architecture Decisions

- Treat packaged lab assets as immutable source inputs and the initialized lab
  directory as the mutable runtime project. Docker Compose, build contexts,
  generated config, `.env`, keys, run archives, and `.aptl/` state operate only
  against the materialized project directory.
- Add one canonical asset materialization boundary for the wheel-owned source
  tree. Do not scatter `importlib.resources` lookups across `certs.py`,
  `env.py`, `credentials.py`, `scenario_catalog.py`, `suricata_seed.py`,
  `snapshot.py`, ACES adapters, or deployment code.
- `aptl lab init <dir>` should materialize every tracked source asset required
  by the public startup path: `aptl.json`, `.env.example`, `docker-compose.yml`,
  `generate-indexer-certs.yml`, `config/certs.yml`, source `config/`
  templates/rules, `scenarios/`, `containers/`, and any scripts or MCP build
  inputs that `docker-compose.yml` or `_LAB_START_STEPS` still reference.
- Never package local generated state: `.env`, `.aptl/`, `keys/`, `.mcp.json`,
  run archives, `config/soc_certs/`, `config/lab-ssh/`, or
  `config/wazuh_indexer_ssl_certs/`. Those remain produced by the existing
  startup steps.
- `aptl lab start` continues to run the existing project-rooted startup
  sequence. It may default to `Path(".")` for operator convenience, but the
  resolved directory must be a materialized project root, not a repository clone
  assumption and not an `importlib.resources` traversable pretending to be a
  Docker build context.

## Cross-Cutting Concerns To Reuse

- CLI and project root: `src/aptl/cli/lab.py`, `resolve_config_for_cli()`,
  `APTL_PROJECT_DIR`, and the existing `--project-dir` convention.
- Lab lifecycle: `orchestrate_lab_start()`, `_LabStartContext`,
  `_LAB_START_STEPS`, `_check_bind_mounts()`, `LabResult`,
  `StartupOutcome`, and `StartupDiagnostic`.
- Config and env: `AptlConfig`, `load_config()`, `find_config()`,
  `load_dotenv()`, `hydrate_dotenv()`, `EnvVars`, `env_vars_from_dict()`,
  `find_placeholder_env_values()`, and `contains_placeholder()`.
- Asset consumers: `sync_dashboard_config()`, `sync_manager_config()`,
  `build_suricata_volume_seeds()`, `ensure_ssl_certs()`,
  `ensure_soc_certs()`, `resolve_scenario_selection()`,
  `load_scenario_catalog()`, `load_compose_profile_index()`, and
  `capture_snapshot()`.
- Deployment boundary: `DeploymentBackend`, `DockerComposeBackend`,
  `SSHComposeBackend`, compose-project scoping, backend timeouts, typed seed
  operations, and argv-list subprocess construction.
- Packaging/release: Hatch config in `pyproject.toml`, the release workflow's
  `python -m build`, `.gitignore`, and tracked-source selection via
  `git ls-files` or an equivalent explicit manifest.
- Observability/persistence: `get_logger()`, `redact()`,
  `RangeSnapshot.to_dict()`, `LocalRunStore.write_json()`,
  `write_jsonl()`, and `append_jsonl()`.

## Security And Validation Layers

- **Package asset gate:** the wheel should include only the explicit source
  asset set. Build/package tests must prove generated secret-bearing paths and
  ignored local state are absent from both sdist and wheel.
- **Materialization path gate:** destination paths must reject absolute paths,
  `..` components, symlinked output chains, and copy targets outside the chosen
  project root before any write. Reuse or extract the containment primitives
  already proven in `aptl.core.credentials` / `_soc_ca_io`.
- **Overwrite gate:** initialization must not silently overwrite `.env`,
  `.aptl/`, generated keys/certs, run archives, or user-edited project files.
  Any replacement policy must be explicit and typed at the CLI boundary.
- **First-party config shape:** durable knobs stay in `AptlConfig` with
  `extra="forbid"`. Do not add a second JSON/YAML config schema for asset roots
  or package manifests unless the canonical config model owns it.
- **Environment binding:** generated `.env` values and placeholders continue
  through `hydrate_dotenv()`, `load_dotenv()`, `EnvVars`, and
  `find_placeholder_env_values()`. Package data must never carry real `.env`
  secrets.
- **Scenario gate:** curated scenario IDs and explicit paths continue through
  `ScenarioCatalog` and the ACES parser. Do not revive a local scenario schema
  or let UI/API code parse `scenarios/` directly.
- **Docker/OS boundary:** Docker Compose runs with `cwd` set to the materialized
  project. Build contexts and bind mounts must be real filesystem paths. Do not
  call raw Docker from a materializer helper or pass secrets in process argv.
- **Remote backend boundary:** existing SSH-remote refusals for locally
  generated artifacts remain valid until the backend grows explicit remote
  materialization. Do not pretend package resources copied locally are visible
  to a remote Docker daemon.
- **Error envelopes:** init/start failures use existing Typer exit and
  `LabResult` shapes. Messages may name the artifact or validation layer, but
  not `.env` values, generated config contents, private keys, raw Docker stderr,
  or raw `icontract` messages.
- **Persistence boundary:** initialized source assets are not run evidence.
  Runtime snapshots and run records continue through `RangeSnapshot.to_dict()`
  and `LocalRunStore` redacting writers.

## Extensibility Seam

The seam is the asset source plus materialized project root, parameterized by
bundle version and an explicit asset manifest. The next reasonable variations
should fit there without re-editing every consumer:

- a different packaged asset version;
- a smaller scenario/profile bundle;
- a future published-image mode that omits local build contexts;
- backend-owned remote materialization for SSH Compose;
- validation of package contents against compose bind mounts and startup-step
  source references.

The seam is not a new deployment backend, scenario schema, run archive schema,
or Docker command passthrough.

## Whole-Repo Surface

- `pyproject.toml`, release workflow, built sdist/wheel, and package-data
  inclusion tests.
- `docker-compose.yml`, `generate-indexer-certs.yml`, Compose build contexts,
  bind mounts, named volumes, profiles, and project labels.
- Source assets under `aptl.json`, `.env.example`, `config/`, `scenarios/`,
  `containers/`, `scripts/`, and `mcp/` when referenced by startup.
- Generated/runtime state under `.aptl/`, `.env`, `keys/`,
  `config/soc_certs/`, `config/lab-ssh/`,
  `config/wazuh_indexer_ssl_certs/`, Docker named volumes, and run archives.
- `src/aptl/cli/lab.py`, `src/aptl/core/lab.py`,
  `src/aptl/core/config.py`, `src/aptl/core/env.py`,
  `src/aptl/core/credentials.py`, `src/aptl/core/suricata_seed.py`,
  `src/aptl/core/certs.py`, `src/aptl/core/soc_ca.py`,
  `src/aptl/core/deployment/`, `src/aptl/core/snapshot.py`,
  `src/aptl/core/scenario_catalog.py`, and `src/aptl/backends/aces*.py`.
- Host/runtime layers: local filesystem permissions, symlinks, subprocess
  argv, Docker daemon cwd, SSH Docker transport, image build cache, and package
  installer layout.
- Repo gates: `.gc/plan-rules.md`, `pytest`, `pre-commit run --all-files`, and
  a clean `aptl lab stop -v && aptl lab start` validation for compose/config
  changes.

## Gotchas And Anti-Patterns

- Treating package data, materialized source assets, generated runtime state,
  Docker volumes, and run evidence as one "asset" concept.
- Running Docker Compose directly from `importlib.resources` or a wheel path
  instead of a real initialized project directory.
- Fixing only `docker-compose.yml` packaging while leaving `config/`,
  `scenarios/`, `containers/`, `generate-indexer-certs.yml`, or startup scripts
  repo-relative.
- Copying ignored local secrets or generated certs into the wheel because they
  exist on one developer machine.
- Adding cwd fallbacks inside individual consumers instead of resolving one
  project root and passing it through existing boundaries.
- Duplicating path containment, env parsing, scenario validation, Docker
  runners, result DTOs, or exception hierarchies.
- Weakening `_check_bind_mounts()` because init is expected to have copied
  files; it is still the startup guard that prevents Docker from creating
  root-owned directories for missing sources.
- Assuming raw `docker compose up` is supported on a fresh init directory before
  `aptl lab start` has generated `.env`, certs, keys, rendered config, and
  Suricata seed volumes.

## Non-Goals

- Do not implement DEP-008 in this preflight.
- Do not redesign Docker Compose, ACES SDL, deployment backends, startup
  readiness, Suricata rule semantics, SOC seeding, or run archive layout.
- Do not switch to published prebuilt images unless a separate requirement
  explicitly replaces local build contexts.
- Do not make the wheel a store for generated runtime secrets, private keys,
  local `.env`, or prior lab state.
- Do not solve SSH-remote asset synchronization without a backend-owned remote
  materialization design.
- Do not require byte-identical regenerated credentials, certs, keys, Docker
  object IDs, image layers, timestamps, or run records across initialized labs.
