# Issue #589 RAES Scenario-Pack Capture Workflow Ownership Preflight

This note records the APTL-side boundary for RAES scenario packs. RAES is the
renamed RAES project; existing `raes_*` package, module, and CLI names remain
technical compatibility identifiers. This is guidance, not an implementation
plan. No new ADR is needed: ADR-035 establishes RAES as the scenario authoring
surface, ADR-046 removes APTL's capture-inventory and parity-inventory surfaces,
ADR-047 owns RAES experiment/capture admission, and ADR-044 owns APTL run
evidence.

## Decision

There are four distinct owners. Their contracts must not be conflated.

| Concern | Owner | APTL boundary |
| --- | --- | --- |
| Portable attack-path, workflow, capture, evidence, and inventory semantics | RAES | APTL consumes the published RAES SDL, contract models, compiler, planner, diagnostics, and controlled vocabulary. It does not mirror them in an APTL schema or taxonomy. |
| Environment-pack format, templates, schemas, validation, release tooling, and adoption guidance | `RAESystem/env-packs` | The companion repository defines how a RAES environment pack is shaped and validated. It does not own the particular experiment, scenario, or execution a downstream user creates with that format. |
| Particular scenario content, experiment design, and execution choices | Downstream scenario or experiment owner | The downstream owner chooses and authors the specific RAES scenario or experiment within the published format and capability constraints. It cannot use that choice to select APTL container names, Compose fragments, host paths, `.env` keys, credentials, shell commands, collector implementations, or backend-specific persistence paths. |
| Runtime realization, lab lifecycle, source acquisition, backend observation, and APTL-local evidence persistence | APTL | APTL lowers an admitted RAES execution plan through the existing runtime target and `DeploymentBackend`, then records backend evidence through the existing snapshot/run-store boundaries. |

Specifically:

- **Attack paths:** RAES defines portable scenario intent and its validation and
  planning semantics. A downstream scenario or experiment owner authors the
  particular intent within the RAES environment-pack format. APTL supplies only actual lab topology,
  participant execution, and observed runtime effects through its declared
  backend capabilities. APTL must not recreate a pack-specific attack-path
  executor, static scenario branch, or local semantic model.
- **Environment-pack format:** `RAESystem/env-packs` owns the reusable pack
  format, templates, schemas, validation, release tooling, and adoption
  guidance. It does not select a particular scenario, experiment, participant,
  or execution for a downstream user.
- **Scenario and experiment choice:** the downstream scenario or experiment
  owner supplies the specific authored content, experiment design, and
  execution choices that use an environment pack. Those choices remain RAES
  inputs and must stay within the admitted format and declared APTL capability;
  they are not an authority over APTL implementation details.
- **Capture:** RAES owns capture-spec semantics, requirement meaning, portable
  evidence records, and inventory methodology. Pack authors select only RAES
  capture requirements. APTL's `CollectorRegistry`/`CaptureBinding` pair is a
  fail-closed apparatus capability mapping to trusted source adapters; it is
  not a second capture schema or a free-text collector selector.
- **Inventory:** RAES owns asset-inventory capture methodology and resulting
  semantic inventory evidence. APTL deliberately has no per-asset capture tree,
  parity inventory, inventory CLI, or runtime-observed scenario content.
  `RangeSnapshot` and realization/run records remain APTL backend observations,
  not portable inventory replacements.
- **Runtime workflows:** RAES owns workflow/evaluation/participant contract
  semantics and plans. APTL's `AptlOrchestrator`, `AptlEvaluator`, participant
  runtime, and `DeploymentBackend` execute only the admitted plan through
  existing runtime and lab lifecycle owners. No scenario-pack workflow engine,
  workflow status model, or exception hierarchy belongs in APTL.

This note is the APTL reference follow-up for issue #589. The cross-repository
follow-ups already named by the issue remain the authorities for their scopes:
[RAES #629](https://github.com/RAESystem/rae/issues/629) for semantic
capture/inventory ownership and
[env-packs #138](https://github.com/RAESystem/env-packs/issues/138) for the
environment-pack format reference. There is no APTL asset migration to create:
the former APTL capture/parity surfaces were intentionally removed under
#690/#757.

## Required Reuse And Validation Passage

An implementation that introduces scenario-pack support, references, or capture
execution must pass every applicable layer below.

| Layer | Required passage |
| --- | --- |
| Pack/artifact ingress | A project-contained scenario continues through `scenario_catalog` containment and `raes.parse_sdl_file`. Any future non-local pack resolver must use ADR-047's bounded, digest-pinned, no-follow authorized-resolver contract; a pack reference is never an ambient path, URL, command, or import search. |
| RAES shape and semantics | Use RAES SDL/experiment/capture public models, semantic compilation, planner diagnostics, controlled vocabularies, and `RuntimeModel`/`ExecutionPlan`. Do not add Pydantic/dataclass mirrors or locally restate capture/inventory validation. |
| Capability and runtime handoff | Build on `create_aptl_manifest()`, `create_aptl_runtime_target()`, `start_raes_scenario()`, and the RAES conformance path. A pack requirement outside the truthful manifest/planner capability is a diagnostic before runtime side effects, never an APTL fallback. |
| Lab and OS effects | Keep container, Docker/Compose, host, network, image, and command effects behind `DeploymentBackend` and the existing `_LAB_START_STEPS` lifecycle. Pack data must not reach raw Docker, shell construction, `curl`, SSH, process argv, or a host filesystem path. |
| Capture source authority | Match declared RAES requirements through the code-owned `CollectorRegistry` and immutable `CaptureBinding`; trusted composition in `core.evidence.adapters.wiring` selects a source adapter. Preserve ADR-041/042 Kali isolation and sidecar ownership, existing SOC clients/`curl_safe`, MCP boundaries, limits, clocks, visibility, and failure outcomes. |
| Config and secrets | Durable non-secret apparatus settings remain strict `AptlConfig`; runtime secrets remain `EnvVars`, placeholder validation, and generated-config owners. No pack may select an environment variable, secret, credential source, host path, or backend provider. Control-plane secrets stay out of SDL, pack metadata, argv, logs, diagnostics, snapshots, and run records per ADR-029. |
| Persistence and observability | Persist APTL evidence through `RunStorageBackend`/`LocalRunStore`, `RangeSnapshot.to_dict()`, and ADR-044's referenced-evidence model, using `pathsafe`, canonical IDs/digests, redaction, and create-once/content-addressed operations. Use `get_logger` and bounded, redacted RAES `Diagnostic`/`LabResult` envelopes; do not log raw pack bytes, backend stderr, captured payloads, paths, or validation input. |
| API/auth surface | This boundary adds no endpoint. Any later pack or evidence API must inherit `verify_token`, `WebAuthSettings`, BFF host/CSRF/session protections, request-size limits, and narrow response projections; it must not expose raw RAES objects or archive paths. |

Canonical verification remains the existing RAES conformance/static/live gates,
pytest, and `pre-commit run --all-files`. Changes to MCP common still require
the dependent MCP builds/tests; changes to Compose, Dockerfiles, or `config/`
retain the clean-lab validation required by `.gc/plan-rules.md`.

## Extensibility And Guardrails

The external seam is a RAES format applied to a downstream-owned immutable pack
artifact binding: `(pack identity, version/digest, scenario entry point) ->
RAES bytes -> RuntimeModel/ExecutionPlan`. APTL may parameterize the
catalog/resolver policy only by authorized trust roots, bounded limits, and
digest requirements. It must not dispatch by pack name, path, or
scenario-specific branch.

The execution seam is the existing `(RAES capture requirement,
CaptureBinding, registration_id, trusted source adapter)` chain. A new source
extends the static registry declaration and its trusted adapter/conformance
fixture; it does not add a pack-controlled plugin, a second manifest matrix,
or a second evidence/workflow state machine.

Avoid these anti-patterns:

- reviving `docs/raes/inventory/`, a parity ledger, `raes-inventory`,
  `runtime-observed:` content, or an APTL-owned capture runner for scenario
  pack inventory;
- treating `RangeSnapshot`, a healthy Compose service, or a collector's empty
  response as semantic inventory/capture success;
- embedding APTL realization specifics in a pack or teaching APTL a RAES
  attack-path/capture DTO, validation layer, exception hierarchy, or workflow
  engine;
- treating the environment-pack format as the owner of a particular scenario,
  experiment, or execution, or treating a downstream scenario choice as an
  authority over RAES semantics or APTL implementation details;
- accepting pack-provided collector IDs as import paths, commands, URLs,
  backend method names, environment names, output paths, or credentials;
- using raw Docker/Compose/SSH/curl calls, bypassing redaction, or leaking
  secrets through errors, OTel attributes, archives, URLs, or process argv;
- confusing a capture admission capability, acquired evidence, a sealed record,
  and a reproducibility/snapshot reference. They are separate lifecycle facts.

## Non-Goals

- No migration of scenario-pack assets, capture bundles, or inventory artifacts
  into APTL.
- No new RAES schema, vocabulary, pack format, import/distribution mechanism,
  inventory methodology, or portable capture/evidence contract in APTL.
- No redesign of the lab lifecycle, deployment backend, collector coordinator,
  Kali sidecar/MCP capture model, run-store layout, exporter, API auth, or
  redaction taxonomy.
- No claim that APTL's current backend evidence is a portable RAES inventory or
  that a pack can demand unsupported runtime capabilities.
