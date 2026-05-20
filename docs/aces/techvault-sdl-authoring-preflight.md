# TechVault ACES SDL Authoring Preflight

This note is the architecture preflight for SCN-010B / issue #319. It is
guidance, not an implementation plan. ADR-035 remains the binding adoption
decision.

## Architecture Decisions

- `scenarios/techvault.sdl.yaml` is an ACES SDL document. Its structural and
  semantic authority is the ACES reference parser (`aces_sdl.parse_sdl_file`)
  and ACES runtime compiler (`aces_processor.compiler.compile_runtime_model`),
  not `aptl.core.sdl`, `aptl.core.scenarios`, or a new APTL model.
- The TechVault SDL must declare scenario structure explicitly enough for a
  generic APTL ACES backend to realize it. A scenario name, preset flag,
  backend hint, or "use legacy TechVault" escape hatch is not parity.
- The parity inventory is the audit authority for legacy coverage. The SDL
  should cite and satisfy relevant `parity#...` rows; it must not copy the
  inventory into a second schema or treat the inventory as runtime input.
- APTL-authored backend realization remains separate from ACES-authored
  scenario meaning. Docker Compose profiles, generated config, readiness,
  endpoint snapshots, and run archives stay owned by the existing APTL
  boundaries named in ADR-035.

## Cross-Cutting Concerns To Reuse

- ACES parser, models, semantic validators, imports, lockfile, and runtime
  compiler from the sibling `../aces-sdl` implementation.
- ACES backend profile and conformance authorities:
  `contracts/profiles/backend/provisioning-only.json`,
  `aces_contracts.backend_profiles.load_backend_profile`,
  `aces_backend_protocols.manifest.backend_manifest_payload`, and
  `aces conformance backend --profile provisioning-only`.
- APTL parity inventory:
  `docs/aces/parity-inventory.yaml`, `docs/aces/parity-inventory.md`, and
  `tests/test_parity_inventory.py`.
- APTL lab/config/runtime owners: `AptlConfig`, `EnvVars`,
  `find_placeholder_env_values`, `_LAB_START_STEPS`, `DeploymentBackend`,
  `LabResult`, `StartupDiagnostic`, `RangeSnapshot.to_dict()`,
  `ENDPOINT_REGISTRY`, and `LocalRunStore`.
- Shared safety helpers and policies: ADR-028, ADR-029, ADR-031, ADR-036,
  ADR-037, `aptl.utils.redaction.redact`, and `aptl.utils.curl_safe`.

## Security And Runtime Gates

- **ACES SDL shape:** the document must pass ACES `SDLModel` closed-world
  validation (`extra="forbid"`), ACES semantic validation, and runtime
  compilation. Do not add local APTL YAML shape checks for ACES fields.
- **Imports and modules:** if imports are used, resolve and verify them through
  ACES `aces sdl resolve` / `verify-imports` / lockfile behavior. Do not fetch
  or execute import content from an APTL helper.
- **Secret classification:** intentional weak target credentials may be
  represented only as lab fixture data. Operator/control-plane secrets
  (`.env`, Wazuh/TheHive/MISP tokens, API passwords, private keys, cookies,
  bearer tokens, generated rendered config) must stay out of the SDL and under
  `EnvVars`, ADR-028, and ADR-029.
- **Environment binding:** durable knobs belong in strict `AptlConfig`;
  runtime secrets belong in `.env` parsed by `load_dotenv` and shaped by
  `EnvVars`. Do not add ACES-specific environment parsing.
- **OS/process exposure:** validation and test commands must not put real
  tokens, passwords, hashes, or private keys in process argv. Existing SOC HTTP
  access keeps using `curl_safe`.
- **Backend/lab execution:** ACES backend work must eventually flow through
  `RuntimeTarget` / ACES operation envelopes into APTL `DeploymentBackend` and
  `LabResult` surfaces. Do not shell out to Docker or parse Compose output from
  SDL authoring or validation helpers.
- **Error envelopes and observability:** parser, compile, conformance, CLI,
  API, snapshot, telemetry, and runstore outputs must report narrow diagnostic
  codes/messages and pass existing redaction boundaries. Do not expose raw
  exception text or dumped ACES/APTL objects if they can contain credentials.
- **Persistence:** generated ACES validation reports or future run evidence
  must use redacted JSON/JSONL boundaries (`LocalRunStore` where run data is
  involved). The SDL itself is source, not generated runtime state.

## Extensibility Seam

The seam is the ACES `RuntimeModel` resource kind plus backend capability
profile, with a small APTL realization map from ACES runtime resources to
existing APTL owners. Add new scenario surfaces by declaring more ACES-native
resources or citing an ACES schema/profile gap. Do not grow TechVault-specific
branches into the public backend contract.

Parameterization belongs in ACES `variables`, imports/modules, and backend
profile declarations. One obvious future scenario in APTL's supported
expressivity class should not require editing a TechVault-only adapter branch.

## Gotchas And Anti-Patterns

- Recreating `ScenarioDefinition`, a Pydantic mirror of ACES SDL, or a
  temporary `aptl.core.sdl` compatibility adapter for `techvault.sdl.yaml`.
- Encoding Docker Compose service names, profile switches, generated config
  paths, or endpoint snapshot fields as ACES scenario meaning unless the ACES
  model explicitly represents that concept.
- Hiding missing ACES expressivity behind `metadata`, `x-aptl-*`, comments, or
  scenario-name dispatch instead of recording an ACES schema/profile gap.
- Copying the parity inventory rows into tests as a second truth source rather
  than reading/citing the inventory.
- Treating designed vulnerable credentials and operator secrets as the same
  class because both are credential-shaped strings.
- Adding new exception, diagnostic, logging, redaction, conformance, or Docker
  helper layers when existing ACES/APTL boundaries already own them.

## Non-Goals

- Do not implement the ACES backend interpreter, conformance runner, live lab
  deployment gate, default-scenario flip, archive move, or deletion of
  `aptl.core.sdl` / `aptl.core.scenarios`.
- Do not change Docker Compose, generated service config, endpoint registry,
  run archive layout, or lab startup ordering while authoring the SDL.
- Do not deprecate DSL/SCN requirements or perform Phase B cutover work from
  this issue.
