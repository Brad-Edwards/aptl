# REP-003 Run-Scoped Provenance Preflight

This note is the architecture preflight for REP-003 / issue #452. It is
guidance, not an implementation plan. No new ADR is needed: ADR-044 owns the
RAES-aligned run-record composition, ADR-029 owns control-plane secret handling,
ADR-047 owns experiment admission and immutable trial planning, ADR-013 and
ADR-023 own deployment interaction, and issue #444 owns the final run seal.
This note fixes how REP-003 crosses those boundaries without creating another
apparatus schema, inventory system, persistence path, validation layer, or
workflow.

## Architecture Decisions And Guardrails

### Compose owner-native identities; do not invent an APTL apparatus model

The run-scoped record is a composition with two deliberately separate
namespaces:

- Portable apparatus and experiment context comes from RAES contracts and
  owner-native serializers: processor manifest, APTL backend manifest and
  capabilities, RAES `RuntimeSnapshot`, admitted source-set/trial/scenario/task/
  capture identities, and participant implementation/configuration provenance.
- APTL backend provenance describes the realized instrument: safe effective
  configuration identity, selected profile and dependency closure, immutable
  image and asset identities, detector/rule/policy content identities,
  collector/tool versions, APTL `RangeSnapshot`, and bounded host/runtime
  facts.

The requirement's ACES terminology maps to the current RAES processor and
contract surfaces in this repository. The legacy `aces` key remains a
read-compatibility concern only. Do not restore an ACES schema, emit an
`AcesRunManifest`, or inspect processor/backend objects through `__dict__`.

The two runtime snapshots remain distinct:

- RAES `RuntimeSnapshot` is portable contract state.
- APTL `RangeSnapshot` is backend-owned range inventory evidence.

Likewise, capture evidence, apparatus provenance, general asset inventory, the
immutable trial plan, and the final seal are related records with different
owners. They may reference one another but must not be flattened into one
schema or state machine.

### Collect at the seal boundary, not by re-discovering the run

The seal coordinator must receive the admitted and executed run context. It
must not reopen the authored scenario, reselect participants or collectors,
recompute bindings against current config, infer a run from the active
directory, or rescan the project as if it represented the past run.

Use the persisted `TrialPlan` and runtime outcomes for source-set, planned
trial, scenario snapshot, task/capture, stochastic seed, realized binding, and
participant configuration identities. Use
`compiled_runtime_model_sha256()` when the compiled RAES runtime model is the
applicable canonical scenario artifact. A display name, source path, module
lock digest, or current file contents are not a canonical scenario snapshot.

The record written by `src/aptl/core/lab.py` during lab startup is a provisional
REP-001 composition. It is currently best-effort, can mint a timestamp run ID,
uses overwrite-capable `write_json("manifest.json")`, and runs before a final
experiment result exists. REP-003 must not label that record as the issue #444
seal or silently retrofit final-trial semantics into the startup step.

The REP-003 output at a real seal point must be a create-once, canonical
provenance input associated with the authoritative run/planned-trial identity.
Until #444 consumes and seals it, call it ready-to-seal provenance rather than
a sealed run. Final signature/attestation and sealed archive state remain with
#444.

### Use a narrow, trusted provenance-provider seam

Use one internal coordinator with code-owned provider registrations, not one
monolithic collector and not a general plugin framework. A registration pins a
stable provider ID, implementation version, the capability/source it supplies,
the owner adapter it needs, applicable seal point, requiredness policy key, and
hard count/byte/time limits. Its ID is never an import path, command, URL,
host path, credential selector, or user-controlled factory.

Each invocation returns a bounded typed result with:

- a closed status such as collected, unavailable, denied, unsupported, timed
  out, or truncated;
- sorted leaf identities and owner-native references/digests;
- stable limitation/reason codes and safe counters; and
- no raw exception, command, environment, arbitrary metadata, or source bytes.

This adapter result is internal backend provenance, not another RAES contract
or capture evidence record. Do not reuse capture-specific status types where
their semantics do not fit, and do not create a new public exception hierarchy.
The coordinator converts internal failures into the small result vocabulary and
safe existing diagnostics.

The extension parameter is the trusted registration set plus a seal profile
(seal point and policy-required provider IDs). Adding the next reasonable
built-in source must require one registration, one narrow owner adapter, and
its conformance tests; it must not require edits to the aggregate record
builder, run controller, RAES DTOs, persistence layout, or exporter. Dynamic
imports and out-of-process third-party providers need a separate authorization
and sandboxing design and are outside REP-003.

### Make identities stable and differences explainable

Use RFC 8785 canonical JSON and an explicit version/domain separator for every
derived structured identity. Normalize SHA-256 values to one representation
(`sha256:<lowercase-hex>`) at the provenance boundary.

Record leaf identities by stable logical role, then compute any family or
aggregate identity over a sorted canonical sequence of
`{logical_id, digest}` entries. This preserves file/role boundaries and makes a
rule, policy, config, image, or collector change affect its own leaf plus its
ancestors. Do not hash an unframed concatenation of file bytes.

Separate stable content identity from volatile observation data. Timestamps,
container IDs, health state, collection durations, and transient host counters
may be relevant observations, but they must not cause otherwise unchanged
apparatus content identities to drift. Image tags are observations; immutable
registry/content digests are identities.

Missing, denied, unsupported, truncated, timed-out, and failed sources are
explicit results, never empty strings, empty maps, absent keys, or a fabricated
digest. A readiness/seal policy maps each result to either a blocking readiness
failure or a declared limitation. REP-003 supplies facts and stable reason
codes; it must not duplicate the readiness workflow owned by #472 or the seal
workflow owned by #444.

### Exclude secrets by source, then enforce redaction as defense in depth

The safe collection rule is allowlist-first. Providers may read only explicit
owner-declared, non-secret sources. They must not ingest a prohibited source
and rely on redaction, hashing, file permissions, or exporter cleanup.

In particular:

- Never read, store, or hash `.env`, raw environment dumps, rendered
  secret-bearing configuration, credentials, cookies, bearer tokens, private
  keys, unrestricted process arguments, or control-plane request/response
  bodies.
- A digest is not safe disclosure for a secret or small guessable domain.
  Secret-shaped digests and hashes of low-entropy settings remain prohibited.
- Build a versioned safe effective-config projection beside the strict
  `AptlConfig` owner. Include only explicit apparatus-relevant fields and their
  effective defaults. Exclude secret values, private-key material, credential
  locators, and privacy-sensitive host/path details unless a separately
  reviewed role requires a bounded public identity.
- Generated configuration is eligible only when its producer declares the
  output non-secret and the provider reads an explicit artifact through a
  contained no-follow path. The ignored `.aptl/config` tree is not eligible.
- Host/runtime inventory is a closed allowlist of validity-relevant facts, such
  as OS/architecture/kernel and deployment-engine mode/version where policy
  requires them. It is not `env`, `ps`, unrestricted `docker inspect`, a
  filesystem crawl, full labels, or all host hardware.

All structured output must still pass the shared redactor and the runstore
secret-invariant check. Redaction detects drift; it does not expand what a
provider is authorized to collect.

## Canonical Incumbents To Reuse

| Concern | Canonical incumbent and required use |
|---|---|
| Processor/backend/capabilities | RAES processor manifest serializers and `src/aptl/backends/raes_manifest.py` (`create_aptl_manifest()` and its public payload/model helpers). Capability claims come from the same code-owned registries that implement them, not a second matrix. |
| Scenario and experiment identity | `src/aptl/backends/raes_runtime_model_artifact.py` and `src/aptl/core/experiment/{spec_loading,admission,admission_artifacts,trial_plan,trial_plan_models}.py`. Preserve canonical admitted identities instead of reparsing authored artifacts at seal time. |
| Participant provenance | `src/aptl/backends/raes_participant_apparatus.py`, participant selection/control-evidence publication, and RAES participant manifest/configuration models. Record the accepted actual selection and configuration digest, not a reconstruction from current config. |
| Realization and profiles | RAES realization/start outcomes, `src/aptl/backends/raes_profiles.py`, and `raes_dependency_closure.py`. Use the realized selection and canonical `ComposeProfileIndex`; the provenance coordinator does not parse Compose. |
| Deployment and runtime facts | `DeploymentBackend`, `src/aptl/core/deployment/`, `host_versions()`, and typed container/network inspection. Extend or normalize this boundary if immutable image identity is missing; never shell out to Docker/Compose from a provider. |
| Range and appliance inventory | `RangeSnapshot.to_dict()`, snapshot endpoint ownership, and `src/aptl/core/appliance_boundary_inventory.py` where the appliance boundary applies. Reference/project these owners; do not broaden the appliance DTO into a general inventory schema. |
| Config and environment | Strict `AptlConfig`, ADR-025, `src/aptl/core/env.py`, `credentials.py`, and producer-owned generated config. A safe config-identity projection is explicit and versioned; `model_dump()` of the whole config and raw config-file hashing are not safe projections. |
| Assets and dependencies | Active participant `asset-lock.json`, release/appliance manifests, `uv.lock`, applicable package lockfiles, and owner-produced dependency closure. Record the lock/artifact actually selected; do not substitute an ambient `pip freeze`, `npm list`, or unrelated release SBOM. |
| Detector and policy content | The producers and canonical config roots for Suricata, Wazuh, policies, allowlists, seeds, and generated rules. Evolve the existing snapshot/content owner rather than add a parallel hashing service, but replace stale broad glob/read and single combined-digest behavior with explicit safe logical sources. |
| Collectors and tools | Admitted capture bindings, `src/aptl/core/experiment/capture_registry.py`, source adapters, `RangeSnapshot.software`, and actual participant/control evidence. Registry declaration is not proof that an implementation ran; preserve the realized version/outcome. |
| Persistence and path safety | `RunStorageBackend`/`LocalRunStore.create_run_json_once()`, RFC 8785, `src/aptl/utils/pathsafe.py`, restrictive create-exclusive/no-follow storage, and the existing content-addressed evidence store for referenced blobs. Do not add a provenance repository. |
| Secrets, logs, and diagnostics | ADR-029, `src/aptl/utils/redaction.py`, TypeScript redaction parity, `src/aptl/utils/logging.py`, safe `AdmissionRejection`, RAES diagnostics, and existing `LabResult` diagnostics in their proper domains. |
| Auth and projection | Existing API bearer verification and BFF host/CSRF/session gates, MCP local authority, sidecar peer checks, and server-side visibility projection. REP-003 adds no endpoint or authority bypass. |
| Export and workflow | `src/aptl/core/exporter.py` packages already-safe artifacts. `.ground-control.yaml`, `.gc/plan-rules.md`, pytest, pre-commit, and the RAES corpus/conformance fixtures remain the completion gates. |

## Security And Validation Passage

The intended design must pass every applicable layer below. Passing a provider's
local shape check is insufficient.

| Layer | Required passage |
|---|---|
| Authority/authentication | Collection is invoked only by the trusted run/seal coordinator for the authoritative run. No new network endpoint is required. Any future API projection inherits bearer verification, BFF host/CSRF/session checks, and visibility filtering; archive presence grants no access by itself. |
| RAES contract validation | Processor, backend, runtime, experiment, capture, and participant fields come from public RAES loaders/models/serializers and admitted runtime objects. Do not locally restate their DTOs or validators. |
| Cross-artifact admission | ADR-047 resolver/spec-loading checks containment, kind/version, joins, apparatus compatibility, participant configuration, capture bindings, and canonical trial-plan persistence before mutation. Seal-time provenance consumes those accepted identities without re-admission or fallback discovery. |
| Provider/result shape | Registrations and outputs use closed code-owned IDs/status/reason vocabularies, unique logical IDs, normalized digests, deterministic ordering, bounded strings/counts, and rejected extra/arbitrary metadata. Hostile labels cannot become keys, paths, log templates, or unlimited record content. |
| Config validation | Durable knobs remain explicit strict `AptlConfig` fields with `extra="forbid"`. Provider registration and readiness policy are trusted code/policy, not arbitrary keys hidden in authored experiment notes or environment variables. |
| Environment and secret binding | `.env`/`EnvVars` and generated credential owners remain the secret boundary. Inject narrow authenticated clients or backend adapters after validation; never give a provider raw env/config, and never place secret-derived material in the config identity. |
| Deployment/source boundary | Docker, Compose, container, network, image, and remote-host facts flow through `DeploymentBackend` and typed owners. SOC access uses established clients and `curl_safe`. Providers do not receive generic shell, HTTP, SSH, filesystem, or controller authority. |
| OS/process exposure | Use argument arrays, incumbent runners, deadlines, and safe temporary-file mechanisms. Do not put tokens, cookies, private-key material, rendered config, arbitrary labels, unrestricted arguments, or secret hashes in argv, URLs, child environments, process titles, or backend diagnostics. |
| Filesystem/path containment | Provider roots and logical files are code-owned. Reject absolute/traversal/NUL/symlink/special-file inputs; use descriptor-relative contained no-follow opens and one verified handle; enforce limits while reading. `glob()`/`rglob()` plus `is_file()`/`read_bytes()` over untrusted or secret-bearing roots is not sufficient. |
| Size/time availability | Enforce per-provider and aggregate byte, file, nesting, string, metadata, and time limits before buffering. Timeout, denial, truncation, and unavailable source remain explicit typed outcomes and cannot silently degrade to success. |
| Secret serialization | Allowlist sources first, then apply shared redaction. `create_run_json_once()` must reject any structured payload changed by redaction. Opaque referenced blobs require an owner classification/policy; exporter is not a sanitation stage. |
| Persistence/identity | Create canonical structured records once under validated run IDs and internally derived paths. A repeated publication is idempotent only for identical canonical bytes; conflicting content fails closed. References identify bytes actually retained. |
| Logging/observability | Log provider ID/version, stage, status/reason code, duration, safe counts, and digest only. Never log content, raw exceptions, pydantic `input`/`ctx`, backend stderr, commands, URLs/headers, host paths, arbitrary labels, or config/env dumps. |
| Error envelope | Normalize parser/backend/provider exceptions at their owner boundary into bounded RAES diagnostics, readiness limitations, or the applicable existing lab diagnostic. Public messages are fixed and safe; detailed logs obey the same secret/metadata constraints. Do not expose `str(exc)` as a record field or API error. |
| Readiness/seal/export | Validate required provider outcomes, owner-native contract models, digest/ref integrity, limitations, and create-once persistence before reporting ready to seal. #472 decides readiness policy and #444 seals. Export packages the already-valid result and cannot repair a leak or missing source. |

## Current Gaps The Implementation Must Not Preserve

- `_hash_config_files()` currently includes `.env` and follows ordinary
  `glob()`/`read_bytes()` paths. `.env` must be excluded, not hashed, and safe
  config identity must come from an explicit effective projection.
- `detection_content_digest()` uses an unframed aggregate and stale,
  non-recursive paths. It misses current nested Suricata MISP content and the
  `config/wazuh_cluster` rule/decoder/allowlist surface, cannot explain targeted
  differences, follows symlinks, and treats no files as an empty success.
- `ContainerSnapshot.image_digest` exists, but the current snapshot population
  path does not prove it is filled with the selected immutable image digest.
  Tags, container names, and container IDs cannot stand in for that digest.
- `_collect_evidence_references()` infers evidence from path presence without
  source outcome, validation, or content digest. Presence is not provenance
  truth.
- The current startup `manifest.json` is best-effort and overwrite-capable.
  A comment calling an archive "now-sealed" does not establish seal semantics.
- `RangeSnapshot.to_dict()` supplies the redacted owner projection, but blindly
  embedding all labels or metadata would still create malicious-key and size
  risks. Use a bounded allowlisted projection/reference for seal provenance.
- The current tool-version projection is a useful start but is not proof of
  collector selection or execution. Declaration, installed version, selected
  implementation, and observed execution are different facts.

## Verification Guardrails

- Prove equivalent owner inputs and different provider/registry iteration order
  produce identical canonical identities. Timestamps and volatile runtime IDs
  must not perturb stable content identity.
- Change one rule, safe config field, image digest, dependency/asset lock,
  collector version, and scenario snapshot independently. Each change must
  affect only its leaf/family identities plus the aggregate.
- Cover raw and nested secret-shaped values, `.env`, rendered config, private
  keys, tokens, cookies, low-entropy secrets, and malicious metadata. Assert
  they enter neither bytes, digests, refs, argv, logs, errors, records, nor
  exports.
- Cover absolute/traversal/NUL paths, symlinks and replacement races, special
  files, hostile logical IDs/labels, oversized files/counts/nesting/metadata,
  slow sources, partial reads, conflicting create-once writes, and concurrent
  collection.
- Exercise unavailable, denied, unsupported, timed-out, truncated, malformed,
  and owner-error outcomes. Assert each becomes the correct limitation or
  readiness failure and never disappears.
- Validate RAES-owned projections through installed RAES models/conformance
  fixtures and backend-owned projections through strict closed models.
- Follow `.gc/plan-rules.md`: Python changes require pytest coverage; MCP common
  changes rebuild/test every dependent MCP; web changes require web tests; and
  Compose, container-Dockerfile, or `config/` changes require a clean
  `aptl lab stop -v && aptl lab start` on a fresh machine. Run
  `pre-commit run --all-files` before completion.

## Gotchas And Anti-Patterns

- Do not create an APTL experiment/apparatus/capability/participant manifest
  that mirrors RAES, or promote APTL backend evidence as a portable contract.
- Do not conflate `RangeSnapshot` with RAES `RuntimeSnapshot`, provenance with
  capture evidence, provider capability with successful collection, inventory
  with a seal, or a digest with attestation/signature/chain of custody.
- Do not rebuild accepted identities from current files/config or silently use
  "latest" manifests, tags, participant models, collectors, rules, or locks.
- Do not add direct Docker/Compose/SSH/curl/shell parsing to the record builder,
  or pass it a complete backend/controller/config/environment for convenience.
- Do not use raw file/config/environment/process dumps, blanket project walks,
  arbitrary recursive mappings, or metadata-controlled paths/commands/URLs.
- Do not treat hashing, redaction, ignored paths, encryption at rest, or file
  permissions as authorization to ingest a secret source.
- Do not put volatile timestamps/container IDs in stable apparatus identity,
  concatenate unframed bytes, omit logical file roles, or make filesystem order
  significant.
- Do not map missing/denied/oversized/unavailable sources to `{}`, `""`, a
  guessed version, a fabricated digest, or generic success.
- Do not duplicate RAES/Pydantic validation, runstore containment, redaction,
  diagnostics, exception hierarchies, readiness transitions, or seal workflow.
- Do not add dynamic provider discovery, imports, subprocess plugins, or a
  generic registry framework. The seam is for trusted built-ins.

## Non-Goals And Boundaries

- REP-003 does not define the #444 signature/attestation format, final archive
  state machine, key management, or chain-of-custody claims.
- REP-003 reports provider outcomes and limitations; #472 owns the readiness
  policy that decides which are fatal.
- It does not redesign RAES contracts, experiment admission/trial planning,
  capture/evidence acquisition, participant execution, deployment backends,
  run storage layout, exporter packaging, web/MCP APIs, or observability.
- It does not create a new asset-inventory methodology. Reuse the existing
  owner and the RAES asset/inventory surfaces; appliance inventory remains
  appliance-scoped.
- It does not produce a forensic host image, raw software/package dump, full
  SBOM, full process/container inspect, secret manager, or detection-policy
  editor.
- It does not promise signed provenance, remote attestation, or reproducibility
  merely because content hashes exist. The record discloses realized apparatus
  facts and limitations for later comparability assessment.

## References

- [ADR-013](../adrs/adr-013-deployment-abstraction.md) and
  [ADR-023](../adrs/adr-023-container-interaction-in-deployment-backend.md):
  deployment/runtime ownership.
- [ADR-025](../adrs/adr-025-strict-first-party-config-schema.md): strict
  first-party configuration.
- [ADR-029](../adrs/adr-029-control-plane-secret-handling.md): secret, runstore,
  snapshot, and argv boundaries.
- [ADR-044](../adrs/adr-044-raes-aligned-run-reproducibility-record.md):
  RAES/APTL run-record composition.
- [ADR-047](../adrs/adr-047-raes-experiment-admission-and-trial-plan-boundary.md):
  experiment admission and immutable trial planning.
- REP-003 / GitHub issue #452.
