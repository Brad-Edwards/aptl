# TechVault Static Validation Preflight

!!! warning "Superseded in part (2026-07-12, issue #690)"
    This is a dated preflight record, kept as written. Where it names the
    captured `scenarios/techvault.sdl.yaml`, the SCN-010 parity inventory
    (`docs/aces/parity-inventory.yaml`), the parity-manifest gate check, the
    `aptl aces-inventory` command, or the per-asset mapping ledgers, it no
    longer describes the repository: all of them were removed in #690. The
    asset-inventory capture capability now lives in ACES; APTL keeps
    `scenarios/techvault-operational.sdl.yaml` as its only driving contract.
    See the Capture Inventory and Parity-Inventory Removal Addendum in
    [ADR-046](../adrs/adr-046-dynamic-aces-scenario-realization.md).

This note is the architecture preflight for SCN-010E / issue #322. It is
guidance, not an implementation plan. ADR-035 remains the binding adoption
decision.

## Architecture Decisions

- The static gate is a composition of existing authorities: ACES parser,
  semantic validation, import lock verification, runtime compilation,
  canonical ACES backend manifest/conformance, APTL parity inventory, APTL
  inventory ledgers, and APTL backend realization tests.
- `scenarios/techvault.sdl.yaml` is validated as ACES SDL through
  `aces_sdl.parse_sdl_file()` and `aces_processor.compiler.compile_runtime_model()`.
  APTL must not add a local Pydantic mirror, YAML shape checker, or
  `ScenarioDefinition` compatibility model for ACES fields.
- Because TechVault uses ACES imports, import/dependency proof belongs to the
  ACES module tooling: `aces sdl resolve` and `aces sdl verify-imports`.
  Missing or stale `aces.lock.json` is a gate failure, not permission to skip
  import verification.
- Backend manifest completion evidence must use the canonical ACES
  `backend-manifest-v2` surface: `aces_backend_protocols.capabilities.BackendManifest`,
  `aces_backend_protocols.manifest.backend_manifest_payload()`,
  `aces_contracts.backend_profiles.load_backend_profile()`, and
  `aces conformance backend --profile provisioning-only`. The provisional
  APTL-local manifest shape in `src/aptl/backends/aces_manifest.py` may remain
  a runtime compatibility bridge only until replaced; it is not conformance
  evidence for this issue.
- Static parity checks are evidence gates, not runtime owners. They may read
  `docs/aces/parity-inventory.yaml`, mapping ledgers, compiled ACES runtime
  resources, and `ApplyResult.details["realization"]`, but must not make those
  audit artifacts a second source of scenario truth.
- Phase A may expose the gate as advisory, but advisory still means visible,
  structured failure. Phase B cutover cannot treat advisory failures, missing
  ACES contract assets, or unavailable conformance CLI wiring as waived.

## Cross-Cutting Concerns To Reuse

- ACES SDL and module authorities: `parse_sdl_file`, `SemanticValidator`,
  `compile_runtime_model`, `resolve_lock_records`, `load_lockfile`, and the
  `aces sdl resolve` / `verify-imports` CLI.
- ACES backend contract authorities: `BackendManifest`, `ProvisionerCapabilities`,
  `BackendCompatibility`, `RealizationSupportDeclaration`, `ConceptBinding`,
  `backend_manifest_payload()`, `BackendManifestV2Model`, backend profile JSON
  under `contracts/profiles/backend/`, and the `aces conformance backend`
  fixture corpus under `contracts/fixtures/`.
- APTL ACES adapter seams: `RuntimeManager`, `RuntimeTarget`,
  `src/aptl/backends/aces.py`, `src/aptl/backends/aces_realization.py`,
  `src/aptl/backends/aces_realization_model.py`, `src/aptl/backends/aces_profiles.py`,
  and `tests/test_aces_backend.py`.
- APTL parity and inventory checks: `docs/aces/parity-inventory.yaml`,
  `docs/aces/parity-inventory.md`, `tests/test_parity_inventory.py`,
  `src/aptl/core/aces_inventory.py`, `src/aptl/cli/aces_inventory.py`, and
  existing per-asset inventory tests.
- APTL lab/config/runtime owners: `AptlConfig`, `EnvVars`,
  `find_placeholder_env_values`, `_LAB_START_STEPS`, `DeploymentBackend`,
  `LabResult`, `StartupDiagnostic`, `RangeSnapshot.to_dict()`,
  `ENDPOINT_REGISTRY`, and `LocalRunStore`.
- Shared safety policies and helpers: ADR-025, ADR-028, ADR-029, ADR-031,
  ADR-036, ADR-037, `aptl.utils.redaction.redact`, `aptl.utils.curl_safe`,
  and `aptl.utils.logging.get_logger()`.
- Repo workflow gates: `.pre-commit-config.yaml`, `.github/workflows/checks.yml`,
  `pyproject.toml`, `uv.lock`, `pytest`, and `pre-commit run --all-files`.

## Security And Validation Layers

- **ACES SDL shape:** closed-world structural validation and semantic
  cross-reference validation are ACES-owned. APTL diagnostics may name the
  failing file, ACES code, row id, or resource address, but not dump the full
  SDL object or raw exception payload.
- **Import trust and dependency shape:** ACES module resolution owns path
  confinement, trust policy, and lockfile comparison. APTL must not fetch,
  expand, or execute imports through a custom helper.
- **Backend manifest shape:** the manifest must be a real ACES
  `backend-manifest-v2` payload and profile-checked against
  `provisioning-only`. Missing concept-authority files, profile JSON, fixtures,
  or CLI entrypoints are actionable failures.
- **Config shape:** durable APTL knobs stay in strict `AptlConfig`; do not add
  ACES-specific keys or pass-through dictionaries to `aptl.json` for the gate.
- **Environment and secret binding:** `.env` remains parsed by `load_dotenv`,
  shaped by `EnvVars`, and placeholder-checked by `find_placeholder_env_values`.
  Operator secrets, rendered config, tokens, cookies, hashes, and private keys
  stay out of SDL, parity manifests, conformance logs, and failure messages.
- **OS/process exposure:** gate commands must not pass tokens, passwords,
  private-key material, or bearer headers in argv. SOC HTTP paths continue to
  use `curl_safe`; static validation should not need SOC API calls.
- **Deployment boundary:** static tests may inspect Compose/profile metadata
  through existing APTL helpers, but runtime/lab interaction remains behind
  `DeploymentBackend`. Do not add raw Docker probes to a static validator.
- **Error envelopes and observability:** ACES-facing failures stay as ACES
  diagnostics or conformance JSON; APTL-facing failures stay in `LabResult`,
  `StartupDiagnostic`, CLI Typer exits, or pytest assertion messages. Use
  `redact()` before logs, CLI/API output, run data, or generated reports.
- **Persistence:** generated validation reports are analysis artifacts, not
  credential stores. Use redacted JSON/JSONL boundaries and `LocalRunStore`
  only for run evidence; do not persist raw ACES/APTL objects that may contain
  secret-shaped payloads.

## Extensibility Seam

The seam is the ACES runtime resource kind plus backend capability profile.
The gate should be parameterized by scenario path, backend profile, ACES
fixtures/profiles roots, and the APTL target name. TechVault is the proving
case; it must not become a scenario-id branch or preset dispatcher.

The next scenario in APTL's supported expressivity class should pass through
the same parser, compiler, conformance, parity-manifest, and realization
checks by changing inputs, not by editing a TechVault-only validator.

## Gotchas And Anti-Patterns

- Treating `src/aptl/backends/aces_manifest.py` as the final manifest contract.
  Its current dataclasses explicitly describe a subset consumed by installed
  planner/runtime code; #322 must replace or wrap that with the canonical ACES
  manifest payload.
- Marking gate tests `integration` or wiring them only behind existing pytest
  hooks without checking the repo filters. CI and pre-commit currently run
  `pytest ... -k "not integration"` for the default Python suite, and the
  local pytest hook is file-filtered; a scenario/doc-only change can skip it
  unless the gate has explicit workflow coverage.
- Letting a missing ACES contract corpus degrade to a warning. A local smoke
  run can fail schema validation if installed contract assets such as
  `contracts/concept-authority/controlled-vocabularies-v1.json` are absent;
  that is an install/tooling failure to fix or report, not a reason to accept a
  local shim.
- Copying parity inventory rows into tests as constants. Tests should read or
  cite the inventory and assert compiled/runtime evidence against it.
- Using `metadata`, comments, `x-aptl-*`, scenario name, file path, or
  `techvault` id as the reason a realization passes.
- Duplicating Docker Compose parsing, profile selection, secret classification,
  redaction, exception hierarchies, startup outcome taxonomies, or conformance
  runners.
- Treating evidence bundles, checksums, screenshots, logs, or mapping ledgers
  as substitutes for ACES SDL encoding when ACES can express the fact.

## Non-Goals

- Do not implement the gate, manifest replacement, conformance wiring, parity
  assertions, live validation, cutover, requirement transitions, or default
  scenario flip in this preflight.
- This preflight did not perform the later ADR-035 cleanup. The local parser
  and legacy scenario paths are now removed or archived by the post-cutover
  reconciliation work.
- Do not broaden the backend profile beyond `provisioning-only`; #311 and #312
  own profile promotion.
- Do not redesign Docker Compose, generated service config, endpoint registry,
  run archive layout, lab startup ordering, API schemas, or web UI behavior.
- Do not file ACES issues as waivers. A linked ACES expressivity issue blocks
  completion until the SDL can encode the surface and the gate passes.
