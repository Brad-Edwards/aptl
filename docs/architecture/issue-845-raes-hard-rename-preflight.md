# Issue 845 RAES Hard-Rename Preflight

This note fixes the architecture guardrails for the ACES-to-RAES cutover. It is
design guidance, not an implementation plan. ADR-025, ADR-029, ADR-035,
ADR-044, ADR-046, and ADR-047 remain authoritative for strict configuration,
secret handling, the upstream SDL/runtime boundary, run records, realization,
and experiment admission.

## Architecture Decisions

- Make one hard runtime dependency cut to the exact `raes==1.1.0`
  distribution. Production and tests must import the owning RAES packages
  directly: `raes`, `raes_backend_protocols`, `raes_conformance`,
  `raes_contracts`, `raes_processor`, and `raes_runtime`. Do not add
  `aces_sdl`/`aces_*` import fallbacks, `sys.modules` aliases, a compatibility
  package, dynamic imports, or broad `ImportError` recovery.
- Treat the package transition as an API migration, not a module-prefix edit.
  A local comparison of APTL's current imports against the cached RAES 1.1.0
  wheel found 340 import statements spanning 46 upstream modules and 144
  imported names. `ExperimentRawEvidenceContentModel` is no longer re-exported
  by `raes_contracts.contracts`; its owning module is
  `raes_contracts.contracts.experiment_capture`. RAES 1.1.0 also adds fields to
  contracts APTL consumes, including `ParticipantRuntimeCapabilities`,
  `ProvisionerCapabilities`, `ExperimentSpecModel`, `ExperimentTaskModel`,
  `ParticipantActionAdmissionRequest`, `RuntimeSnapshot`,
  `WorkflowStepExecutionState`, `RuntimeControlPlane`, `RuntimeTarget`,
  `Scenario`, and `InstantiatedScenario`. Every imported name and every
  APTL-constructed contract must therefore be exercised against RAES 1.1.0;
  symbol presence alone is insufficient.
- Keep APTL as a RAES backend adapter. The newly available
  `raes_reference_backend`, `raes_backend_libvirt`, `raes_backend_stubs`,
  `raes_operations`, and `raes_mcp` packages do not replace APTL's
  `DeploymentBackend`, realization, boundary enforcement, evidence, secret, or
  lifecycle owners merely because they now ship in the same distribution.
  Any ownership transfer is separate architecture work with behavioral and
  security parity evidence.
- Rename Python modules, identifiers, logger names, check names, documentation,
  and current UI/API descriptions to RAES. `APTL_ACES_TARGET_NAME` and
  `APTL_ACES_TARGET_VERSION` are Python constants, not environment variables:
  rename the identifiers, but preserve the serialized runtime-target values
  `aptl` and `0.1.0` unless the backend manifest contract independently changes.
  Do not create new `APTL_RAES_*` environment settings for constants that are
  not configuration.
- Invoke the installed `raes` executable through the existing fixed-argv,
  no-shell conformance/import-gate runner. Installation of the additional
  `raes-mcp` console script does not authorize APTL to start it, add a listener,
  register it in Compose/workbench configuration, or expose it through the web
  control plane.

## Persisted And Wire Identities

New APTL-owned artifacts use RAES terminology; historical artifacts are not
rewritten in place.

- Bump the run record to `aptl.run-record/v2`. New writers emit the portable
  contract section under `raes`, never `aces`. Within its scenario projection,
  use the role-based key `module_lock_digest` rather than carrying either brand
  in an APTL-owned field.
- Put v1 compatibility behind one schema-aware run-record accessor. It selects
  `raes` for v2 and `aces` for v1. Required-validation paths reject an unknown
  version, a version/key mismatch, or a record carrying both sections;
  best-effort correlation treats an invalid/ambiguous portable section as
  absent and never merges the two. No writer emits v1.
- Update the participant-qualification evidence validator to recognize the
  exact supported run-record versions rather than silently changing v1's
  meaning. Existing content-addressed run records, qualification reports,
  signatures, and archive digests remain byte-for-byte historical evidence.
- Bump the APTL boundary inventory to
  `aptl.appliance-boundary-inventory/v2`. Its active authority is `raes` (or
  `platform`), its trusted route identity uses the already canonical
  `participant_routes_digest`, and its required-policy flag uses
  `raes_boundary_required`. Boundary specs, strict observations, findings,
  in-memory receipts, helper input, and the nftables ownership comment must
  change as one contract. Active readers do not accept `aces` as a second
  authority; old v1 inventory remains historical evidence.
- New live-gate evidence uses `raes_specification`. Do not keep both category
  values in the active failure taxonomy or reinterpret old evidence in place.
- Upstream-owned identities are not APTL rename targets. Semantic references,
  lock/trust filenames, lock schema values, media types, contract IDs, and
  corpus payloads must use exactly what the installed RAES parser and published
  corpus define. RAES 2.0.0 now publishes `raes.lock.json`; consumers continue
  to read the public `LOCKFILE_NAME` constant instead of manufacturing or
  preserving either namespace locally. Historical contract literals remain
  unchanged only where the upstream contract still owns them.

## Existing Contracts To Reuse

| Concern | Canonical owner and required reuse |
|---|---|
| SDL and runtime validation | RAES `parse_sdl` / `parse_sdl_file`, semantic validation, compiler/planner, `RuntimeManager`, published contract models, and conformance corpus remain the only upstream schema authority. Do not add local mirror DTOs or structural revalidation. |
| Experiment admission | `core/experiment/spec_loading.py`, `admission_artifacts.py`, `admission_steps.py`, `apparatus.py`, `policy.py`, `capture_registry.py`, and `errors.py` already own size/count/depth limits, identity joins, capability checks, policy mappings, and redacted rejection diagnostics. |
| Backend adaptation | The current `backends/aces*.py` modules (renamed in the cutover), backend manifest, diagnostics, realization, provisioner, orchestrator, evaluator, participant runtime, and observation layers remain the APTL adapter boundary. `DeploymentBackend` remains the Docker/Compose/host authority. |
| Boundary enforcement | `ApplianceBoundaryPolicy`, `ApplianceBoundaryBinding`, strict observation models, `boundary_compiler`, `ComposeBoundaryRealizationMixin`, and `containers/network-boundary-helper/helper.py` own the closed policy, digest binding, fail-closed compilation, kernel realization, and readback proof. |
| Persistence and redaction | `LocalRunStore`, `RunStorageBackend`, `RangeSnapshot.to_dict()`, evidence persistence, exporter packaging, `aptl.utils.redaction.redact`, safe relative-path validation, and Python/TypeScript redaction parity remain the only serialization boundaries. |
| Config and secrets | Strict `AptlConfig`, `load_config()`, `EnvVars`, dotenv hydration, placeholder checks, generated-file containment/atomic writes, `curl_safe`, and ADR-029 remain mandatory. The rename adds no config key or secret source. |
| Errors and observability | RAES `Diagnostic`, the existing backend diagnostic renderer, experiment-admission normalizer, `LabResult`, `StartupDiagnostic`, `get_logger()`, and OTel remain the error/logging vocabularies. Rename them; do not fork them. |
| API and UI | Existing scenario projection DTOs, `verify_token` / `WebAuthSettings`, router dependencies, CSRF/websocket gates, and redacted HTTP error projection remain unchanged except for current terminology. No upstream model is exposed directly. |
| Dependency and release policy | `pyproject.toml`, `uv.lock`, blocking `pip-audit`, OSV/Trivy jobs, cross-platform install/tests, release-wheel build, and CycloneDX SBOM are the dependency authority. Because APTL imports `blake3` directly, it must be declared directly rather than relied on through RAES transitively. |
| Workflow and quality | `.ground-control.yaml`, `.gc/plan-rules.md`, `.pre-commit-config.yaml`, `.github/workflows/checks.yml`, SonarCloud, pytest, the static/live RAES gates, strict MkDocs, and Vale remain the completion path. Do not add exclusions for renamed files. |
| Agent inventory tooling | The existing installer behavior stays idempotent and collision-safe, but its command, `RAES_REPO` input, checkout discovery, and `raes-asset-inventory-capture` source/targets must follow the renamed upstream skill. Do not leave parallel ACES and RAES installations managed by APTL. |

The upstream runtime snapshot serializer currently used by the run-record
builder is a private RAES function. Keep that dependency isolated at the
existing run-record adapter and contract-test its complete output. Do not copy
the serializer into APTL. A future public RAES serializer should replace this
single call site.

## Security And Validation Passage

| Layer | Required behavior |
|---|---|
| Package and supply chain | Resolve one hashed RAES 1.1.0 graph in `uv.lock`; reconcile the exact `z3-solver==4.16.0.0` pin and RAES floors with APTL's direct constraints. Preserve blocking `pip-audit`, cross-platform installation, OSV/Trivy visibility, and release SBOM coverage. No runtime package download or fallback index is added. |
| Authored input and contract shapes | Untrusted SDL, experiment specs, tasks, capture specs, associated artifacts, and manifests continue through RAES/Pydantic closed schemas and APTL's existing byte/count/depth and identity/capability gates before planning or mutation. New optional RAES fields do not become implicitly supported APTL capabilities. |
| Backend manifest and planning | Build identity only through the canonical manifest factory and validate the exact RAES 1.1.0 profile/corpus in process and through `raes conformance backend`. Parser success alone does not establish conformance or realization support. |
| Boundary and OS realization | Rename the authority across the strict Python literal models, compiled policy JSON, helper validator/renderer, receipt map, readback observations, probes, and nftables comment atomically. An unknown or legacy active authority fails closed; it must not fall through to platform rendering or disable strict base-container network binding. |
| Configuration and environment | Add no rename-specific config or environment alias. Existing strict unknown-key rejection, environment hydration, placeholder checks, and generated-file protections continue to apply. Target identity constants never pass through env binding. |
| Authentication and listeners | The change adds no route, auth mode, port, service, or MCP registration. Existing API, websocket, and workbench requests stay behind their current auth/CSRF/allowlist boundaries. The transitively installed `raes-mcp` is inert unless separately designed and authorized. |
| Process exposure | Resolve `raes` with the existing trusted executable lookup and invoke it as an argument array with `shell=False`, fixed subcommands, bounded timeouts, captured output, and redacted/bounded failure detail. No scenario content, credential, token, private path, or rendered config is put in argv or logs. |
| Errors and logs | Reverify RAES 1.1.0 exception shapes before retaining pass-through text. Continue to drop Pydantic `input`/`ctx`/`url`, scrub paths, redact messages, cap rendered diagnostics, and send only full redacted diagnostic sets to the existing logger. Never catch a broad import/API failure and continue with an empty plan. |
| Persistence and export | Version before changing shape; write through redacting runstore methods; preserve path containment; keep portable RAES runtime state separate from APTL `RangeSnapshot`; and leave exporter code packaging-only. Compatibility reads do not rewrite or resign evidence. |

## Extensibility And Whole-Repository Scope

The extensibility seam is the existing RAES/APTL adapter boundary: RAES owns
authored and portable contract models; APTL owns backend realization and
evidence. Runtime target name, backend profile, corpus roots, scenario path,
and run identity remain parameters. The single run-record section accessor is
the only legacy-read seam. A future RAES schema/profile or public serializer
changes that adapter and its conformance tests; it does not require another SDL
model, exception hierarchy, or archive reader. A future boundary authority is
an explicit versioned enum/schema addition, not an open string.

The whole-repository cutover includes:

- dependency metadata/lock, wheel/SBOM and vulnerability workflows, CI,
  pre-commit file filters and manual gate names;
- all six upstream Python import roots, APTL backend modules, experiment and
  evidence consumers, validation gates, API projections, CLI handoff, and
  package asset references;
- run-record writers/readers/qualification checks, boundary models/compiler,
  Compose receipts, base-container strictness, the network-boundary helper, and
  persisted finding/category strings;
- scenario catalog and SDL files, while preserving only contract-owned legacy
  URNs/lock identities emitted by RAES 1.1.0;
- tests, fixtures, examples, current docs/ADRs/navigation, web terminology,
  installer/agent guidance, and active changelog fragments. Per repository
  policy, do not edit `CHANGELOG.md` or the project version.

## Gotchas And Anti-Patterns

- Do not stop after replacing the 80 `aces_sdl` imports; APTL imports five
  additional upstream package families extensively.
- Do not trust import success as API compatibility. Exercise constructors,
  serializers, validators, planners, manifest/profile conformance, exception
  normalization, and representative static/live scenarios.
- Do not let both old and new upstream distributions resolve in one
  environment. That can create distinct enum/model class identities and
  misleading `isinstance` failures.
- Do not change a persisted key under a v1 schema, merge `aces` and `raes`
  mappings, use last-one-wins behavior, or rewrite content-addressed archives.
- Do not blindly replace contract-owned `urn:aces:*` or upstream lock/trust
  names. Conversely, do not use those exceptions to retain ACES in APTL-owned
  identifiers or current prose.
- Do not equate RAES `RuntimeSnapshot` with APTL `RangeSnapshot`, RAES backend
  references with `DeploymentBackend`, or a target constant's Python name with
  its serialized target identity.
- Do not expose `raes-mcp`, broaden web/MCP auth, add a service, or move web
  dependencies into product behavior simply because the distribution installs
  FastAPI, Uvicorn, AsyncSSH, and MCP.
- Do not duplicate RAES schemas, the admission validator, boundary policy,
  redaction, diagnostic renderer, config/env parsing, CLI subprocess policy, or
  conformance workflow.
- Do not suppress Sonar findings, exclude renamed files, compress code, or
  perform unrelated backend replacement to avoid new-code findings.

## Non-Goals And Boundaries

This issue does not redesign RAES contracts, adopt RAES's reference/libvirt
backend in place of APTL, change the APTL backend profile or serialized target
identity, expose RAES MCP, add API/config/env surfaces, redesign run archives,
rewrite historical evidence, replace deployment backends, or change secret,
auth, telemetry, exporter, lifecycle, participant-profile, or appliance-release
architecture. It does not add a generic compatibility framework, dependency
injection layer, repository/service abstraction, exception hierarchy, schema
mirror, or second validation workflow.
