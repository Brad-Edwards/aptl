# EXP-008 Portable Research Evidence Bundle Preflight

This note is the architecture preflight for EXP-008 / issue #472. It is
guidance, not an implementation plan. No new ADR is needed: ADR-029 owns
secret handling, ADR-044 owns the distinction between RAES contracts and APTL
backend evidence, ADR-047 owns experiment admission and immutable source
identity, EXP-010 owns evidence acquisition, OBS-002 owns correlation and clock
context, REP-003 owns ready-to-seal provenance, and issue #444 owns the actual
run seal. EXP-008 composes those authorities into a portable package; it does
not replace any of them.

The requirement uses the historical ACES concept name. This repository has
completed the hard Python namespace cutover to RAES 2.0. Canonical experiment
artifacts therefore enter through `raes_contracts` and the published RAES
corpus. The removed `aces_*` Python packages must not be reintroduced.

## Architecture Decisions And Guardrails

### Export one verified closure, never an ambient run directory

Bundle assembly consumes the verified artifact closure produced by the #444
seal boundary: an immutable manifest/root identity plus the exact regular-file
bytes it covers. It must not infer sealing from any of the following:

- a run directory or `manifest.json` being present;
- `seal_state="ready-to-seal"` in REP-003 provenance;
- `AcquisitionDisposition.SEALED_READY`;
- a `checksums.sha256` file; or
- `ExperimentRunModel.run_status="sealed"` without verification of the seal
  that binds the complete artifact closure.

The final seal must cover the bundle inventory and every included canonical or
derived artifact. If projections are assembled after an earlier source-run
seal, #444 must bind the final bundle root as well; copying a signed source
manifest beside unsigned projections is not a sealed bundle. EXP-008 does not
create a second signing-key format, trust-anchor model, or attestation
hierarchy.

Partial, failed, aborted, invalidated, and inconclusive runs remain exportable.
Their canonical run status, capture outcomes, provenance limitations, missing
references, redaction/loss disclosures, and seal scope remain intact. A
limitation can make a bundle incomplete for a declared purpose without making
the available bytes unexportable. The exporter must never upgrade such a run
to complete, successful, publishable, or study-fit.

Current repository state makes the seal input a real dependency gate:

- admission validates authoring input, task, scenario, and capture artifacts,
  but persists the internal trial plan under the sibling
  `experiment-plans/` namespace rather than retaining every canonical source
  byte in a run-scoped sealed closure;
- EXP-010 publishes RAES evidence records and content-addressed evidence bytes;
- REP-003 publishes ready-to-seal provenance, not a seal; and
- no production path currently constructs the final RAES
  `ExperimentRunModel`.

EXP-008 must not repair those gaps by re-resolving project paths after the run.
The #444/run-finalization contract must supply the exact task, authoring input,
run, apparatus, capture, evidence, provenance, and referenced observation bytes
that were pinned while the run was authoritative. If a partial historical run
lacks one, the bundle records a stable missing-source limitation rather than
substituting current project content or fabricating an artifact.

### Preserve canonical contracts; add only a packaging envelope

RAES remains the authority for task, authoring-input/spec, run, apparatus
context, capture, evidence, reference, disclosure, and associated-artifact
shapes. Validate canonical JSON artifacts through the public RAES models and
semantic/conformance APIs, and include their original sealed bytes. Do not
round-trip an accepted artifact through `model_dump()` merely to make its
format prettier: that can change absent/default fields, formatting, number
representation, and therefore identity.

Use the published, language-neutral JSON Schemas from
`raes_contracts.corpus` (`corpus_family_root(SCHEMAS)`) and the publication
records beneath the same public corpus. Do not generate approximate schemas
from APTL DTOs, copy the fixture corpus into this repository, or assume a
site-packages path. The bundle includes the exact schemas needed by its
canonical artifacts, their checksums, contract identifiers, RAES distribution
version, and the publication metadata needed to identify them. JSON Schema
validity is structural; the bundle also discloses which semantic/conformance
validation was performed and its limitations.

One minimal versioned APTL bundle envelope is necessary for packaging metadata.
It may describe the bundle profile, seal/root identity, artifact inventory,
data dictionary, projections, validation disclosures, and limitations. It must
not restate fields already owned by a RAES artifact. An inventory row references
the canonical artifact by path, logical role, contract/schema identifier,
digest, and source reference; it does not copy task/run/evidence fields into a
second APTL schema.

The existing `aptl.run-record/v2`, `RangeSnapshot`, REP-003 provenance, and
OBS-002 correlation projection remain explicitly APTL/backend-owned evidence.
They may be included and identified as such, but must not be labelled as the
portable RAES experiment run, apparatus context, evidence record, or source
contract.

### Inventory, data dictionary, and integrity root

The bundle inventory is the only packaging-level source of truth. Build it from
the verified seal manifest and explicit RAES/APTL references, never from
`Path.rglob()`. Every included regular file has:

- one code-owned, normalized, relative POSIX bundle path;
- a stable logical role and canonical-versus-derived classification;
- its source artifact/reference identity and applicable contract/schema or
  mapping version;
- SHA-256, byte size, and a validated media type;
- sensitivity and participant visibility where applicable;
- redaction, withholding, transformation, and loss disclosures;
- provenance and clock references where applicable; and
- explicit limitation codes rather than silent omission.

Bundle paths are short, ASCII, and derived from code-owned roles, validated IDs,
and content digests. A raw observation's filename, URI, media type, Unicode
spelling, or metadata never becomes an archive entry name, extraction
destination, parser choice, shell argument, or HTTP header. Preserve such a
source name only as bounded data in a structured record when the owning
contract permits it.

Inventory and packaging metadata use RFC 8785 canonical JSON, normalized
lowercase `sha256:<hex>` identities, deterministic ordering, and domain/version
separation consistent with `trial_plan`, `provenance.identity`, and the
create-once run store. The inventory root excludes wall-clock creation time,
host-absolute paths, temporary paths, file-system metadata, locale, and
iteration order. If human-facing creation metadata is included, it is clearly
outside the reproducible identity. A checksum file never includes or rewrites
itself.

The data dictionary references the included RAES JSON Schema for canonical
artifacts. For a projection it additionally records source contract and field,
target field and physical type, null/missing/unavailable treatment, timestamp
and integer encoding, nested-reference handling, mapping identifier/version,
and every known loss. It is metadata about a mapping, not a second canonical
data model.

### Projections are optional, derived, and loss-accounted

Canonical source records and their references are always retained. JSONL,
Parquet, and OCSF-aligned outputs are optional derived artifacts selected by a
closed export policy. A projection is admitted only when a versioned, tested
mapping declaration names its source contract versions, target format/schema
version, field mapping, type/null rules, reference preservation, and loss
disclosures. Unknown formats, mappings, or source versions fail closed; no
best-effort flattening or guessed columns.

Round-trip semantics are load-bearing:

- missing, explicit `null`, unavailable source, withheld value, and redacted
  value remain distinguishable;
- identifiers stay strings even when digit-shaped;
- timestamps retain their exact instant, offset/clock domain, precision, and
  uncertainty rather than becoming locale-dependent text or floating-point
  epoch values;
- integers are never routed through IEEE-754 floats, and values outside a
  chosen Parquet integer width use an explicitly declared exact encoding or
  make that projection ineligible;
- nested evidence references remain typed nested structures or canonical JSON
  with a declared mapping, never delimiter-joined strings; and
- row order is either semantically specified or canonicalized and documented,
  never inherited from filesystem or map iteration.

The existing `mcp-side/ocsf.jsonl` is an OCSF-aligned derivative whose
classifier, extractor, redaction, and field vocabulary are owned by
`mcp/mcp-red` and `docs/red-team-taxonomy.md`. It can be included with its
source tool-call references and an explicit APTL mapping/taxonomy version. It
must not be presented as an official OCSF-conformant transformation without a
pinned OCSF schema/version and passing validator. A new OCSF projection reuses
that taxonomy owner; it does not rebuild classification in Python.

`src/aptl/core/detection.py` contains scoring and coverage functions. They are
not an export projection. Bundle assembly must not call detection matching,
coverage scoring, effect-size/statistical code, chart/report generation, claim
selection, or any function that interprets evidence quality as a research
result.

CSV is not a v1 bundle projection. This avoids turning faithful source strings
into executable spreadsheet cells. If a future version adds CSV, its mapping
must neutralize leading formula markers and control characters in the derived
cell only, disclose that transformation, and retain the unmodified canonical
source. Never prepend formula escapes to canonical JSON or raw evidence.

### Deterministic archive and separate transport

Bundle construction is local and offline. The logical bundle contract is
independent of its archive compression and remote destination:

- enumerate only the sealed inventory;
- open every source regular file once with descriptor-relative no-follow
  containment and hash/read from that handle;
- reject symlinks, hard links, devices, sockets, FIFOs, path aliases, duplicate
  normalized names, and files that disagree with their sealed size/digest;
- sort members by normalized bundle path;
- normalize archive uid/gid, names, modes, timestamps, and format-specific
  headers;
- use fixed, versioned compressor settings or no compression; and
- publish through an owner-only candidate plus create-once/atomic link, never
  overwrite a prior bundle or write the output beneath the input run tree.

`src/aptl/appliance/offline.py` and `aptl.appliance.manifest` establish the
repository's deterministic USTAR metadata, no-follow reads, candidate output,
create-once publication, canonical manifest, and checksum/signature patterns.
Reuse or generalize only their archive mechanics; do not import the
appliance-specific closed staging allowlist into research export.

The current `src/aptl/core/exporter.py:export_local()` is a legacy convenience
archive, not the EXP-008 builder. It scans the ambient run tree, writes
`checksums.sha256` back into that tree, and uses time-bearing tar/gzip metadata.
That mutates the purported input and is not repeat-deterministic. Do not wrap
it and call the result a research bundle.

Remote upload remains a transport adapter after local verification. It receives
the already-complete bundle and its digest and must not rebuild, retag from
hostile record values, upload an extra mutable manifest, or alter archive
bytes. Bucket and prefix are non-secret validated inputs. Credentials remain in
the incumbent SDK credential provider and never enter experiment documents,
bundle metadata, process argv, URLs, logs, or exception text.

### Verification is streaming and resource-bounded

A third-party verifier must be able to validate the bundle inventory, every
artifact digest/size, the seal/root binding, included RAES schemas, and declared
mapping versions without importing APTL internals. Verification operates on
archive streams or a private destination; it never uses `extractall()`.

Archive entry count, individual stored/uncompressed bytes, total bytes, path
length/depth, metadata length, decompression ratio, parser nesting, JSONL row
size/count, and projection resources are hard-bounded before allocation or
extraction. Reject duplicate paths, absolute paths, `.`/`..`, backslashes,
NUL/control characters, Unicode-confusable path aliases, links, special files,
trailing-data ambiguity, and inventory/archive disagreement. Limits and format
profile are part of the versioned bundle contract, not hidden CLI defaults.

## Cross-Cutting Incumbents To Reuse

| Concern | Canonical incumbent and required use |
|---|---|
| RAES contracts | Exact `raes==2.0.0`, public `raes_contracts` models/loaders, semantic/conformance APIs, and `tests/test_raes_namespace_cutover.py`. Do not import removed `aces_*` packages or write legacy `aces` sections. |
| Published schemas | `raes_contracts.corpus.corpus_root`, `corpus_family_root(SCHEMAS)`, schema-publication records, and installed corpus fixtures for validation tests. Do not reconstruct package paths or emit local mirrors. |
| Admission and source identity | `src/aptl/core/experiment/{resolver,spec_loading,admission,admission_artifacts,trial_plan,errors}.py` for bounded loading, exact source digests, safe diagnostics, and deterministic identities. Export consumes their sealed outputs; it does not rerun resolution. |
| Evidence | `src/aptl/core/evidence/{records,content_store,_persist,outcomes,visibility}.py` for RAES evidence records, content-addressed bytes, digests, loss/redaction state, explicit refs, and visibility. |
| Provenance and correlation | `src/aptl/core/provenance/**`, `src/aptl/core/correlation/**`, ADR-044's `raes_repro.py`, and `raes_runtime_model_artifact.py`. Preserve their namespaces and limitation semantics. |
| Seal boundary | Issue #444's verified seal/root and attestation contract. `ready-to-seal` and `sealed-ready` are handoff states only. EXP-008 adds no parallel seal or trust store. |
| Persistence and containment | `RunStorageBackend`/`LocalRunStore`, public create-once methods, RFC 8785, `src/aptl/utils/pathsafe.py`, and the content-addressed evidence layout. Do not add an export repository or duplicate private run-store validators. |
| Archive mechanics | `src/aptl/appliance/offline.py` and `aptl.appliance.manifest` for deterministic member metadata, no-follow hashing, canonical manifests, candidate files, and create-once publication. |
| Secrets | ADR-029, `src/aptl/utils/redaction.py`, TypeScript parity in `mcp/aptl-mcp-common`, evidence sensitivity/visibility policy, and run-store secret invariants. Export is never the first redaction boundary. |
| OCSF alignment | `mcp/mcp-red/{logger,classifier,extractor,capture}.ts`, `docs/red-team-taxonomy.md`, ADR-027, and ADR-033. Reuse the existing field taxonomy and raw tool-call reference. |
| Errors and observability | RAES `Diagnostic`, `AdmissionRejection`, capture/provenance stable reason codes, `render_raes_diagnostics()`, and `get_logger()`. Log fixed stages, IDs, mapping versions, counts, sizes, durations, and codes only. |
| Config and auth | Strict `AptlConfig`, `RunStorageConfig`, `EnvVars`, `resolve_run_store()`, API `verify_token`, and BFF Host/CSRF/two-factor session gates. Add no experiment-provided env/config keys or unauthenticated download route. |
| Workflow and dependencies | `.ground-control.yaml`, `.gc/plan-rules.md`, `pyproject.toml`, `uv.lock`, hashed `requirements/*.txt`, pytest/fuzz tests, pre-commit, and MCP dependent builds when common/OCSF code changes. |

The create-once implementation has two current call surfaces:
`LocalRunStore.create_run_json_once()` and the older helper in
`evidence.content_store`. New bundle code should use the public run-store
surface or a genuinely shared persistence primitive, not add a third copy of
canonicalization, secret checks, ID validation, or no-follow conflict handling.

## Security And Validation Passage

The intended design must pass every applicable layer below.

| Layer | Required passage |
|---|---|
| Authentication/authority | The initial surface is local CLI only and adds no network listener. A future API download inherits `verify_token` and BFF Host, strict same-origin/CSRF, cookie plus session-header gates. Download filenames and `Content-Disposition` are server-derived ASCII, and responses use a fixed media type plus `nosniff`. |
| Seal authority | Verify the #444 root/signature/attestation against its configured trust input before packaging, and bind the final inventory plus projections. A status string or checksum list is not authority. |
| RAES shape/semantics | Validate each canonical artifact with its public RAES model and applicable semantic/conformance gate. Preserve original sealed bytes and include the authoritative published schema/version. Drop pydantic `input`, `ctx`, and raw exception text from errors. |
| Cross-reference closure | Resolve only explicit sealed references; verify kind, id, version, path, digest, size, capture requirement, run/task/apparatus joins, and visibility. Missing or dangling refs become stable limitations, never ambient lookups. |
| Projection policy | Accept only code-owned mapping IDs/versions and closed requested formats. Check source contract version, exact type/null/reference rules, declared losses, and output validation. No dynamic imports, expressions, templates, or user-selected callables. |
| Config/environment | Durable settings, if any, enter strict `AptlConfig`; one-shot selections use a strict bounded request shape. Bundle construction never hydrates or reads `.env`, `EnvVars`, API tokens, SDK credentials, generated config, private keys, or arbitrary environment variables. |
| Secret/sensitivity | Canonical inputs must already have passed their owning capture/persistence policy. Re-apply secret-invariant checks to new structured bundle metadata, but do not silently redact identity-bearing canonical bytes. Opaque prohibited secrets fail/exclude with a limitation; designed target evidence retains explicit sensitivity. |
| Filesystem input | Start from a trusted seal root, validate code-owned relative POSIX paths, walk/open descriptor-relative with no-follow semantics, require regular files, and hash/read one handle. Never `resolve()` then reopen, follow links, or scan unlisted files. |
| Filesystem output | Require an output outside the input tree, owner-only parent, randomized candidate, normalized read-only final mode, atomic create-once publication, and no overwrite/symlink target. Cleanup may remove only the exact private candidate. |
| Archive reader/writer | Normalize metadata and order; reject links, specials, duplicate/alias paths, traversal, hostile Unicode/control characters, oversized headers/members/totals, and unsafe decompression ratios. Verify before any extraction and never call `extractall()`. |
| Formula/media/filename | Use code-owned paths and media dispatch. Treat declared media type and source filename as data, not parser or extension authority. Emit no CSV in v1; future spreadsheet projections escape derived cells with an explicit loss mapping while retaining source bytes. |
| OS/process exposure | Bundle construction needs no subprocess, Docker, Compose, curl, ssh, or shell. A Parquet library is called in-process with resource limits. Remote credentials never appear in argv, child env, URLs, or archive metadata. |
| Error/log envelope | Normalize failures to stable export-domain diagnostics and existing reason-code style. Never log/return raw archive metadata, source values, absolute paths, URLs, headers, SDK errors, captured bytes, commands, secrets, or stack traces. |
| Transport | Build and verify locally first. Remote transport accepts exact path/digest/size, validates bucket/prefix, URL-encodes any allowlisted tags, and uploads one immutable bundle without rewriting it. |
| Independent verification | The bundle carries its packaging schema, relevant RAES schemas/publication identity, inventory, mappings, checksums, and seal material. Verification requires no APTL import and enforces all resource limits while streaming. |

`APTL_EXPERIMENT_NO_REDACT` is not an export switch. It does not disable OTel,
run-store, snapshot, stderr OCSF, or final-bundle secret safety, and it cannot
authorize inclusion of control-plane secrets.

## Extensibility Seam

The extension seam is a closed, versioned projection selection over an
unchanged verified artifact closure. A reasonable next format adds one pure
mapping declaration/implementation and conformance fixture, then appears in the
bundle's projection inventory. It does not edit RAES models, evidence
collectors, run finalization, archive path rules, seal verification, or remote
transport.

Keep three parameters separate:

1. the verified seal/profile that chooses the canonical artifact closure;
2. the requested `(format, mapping_version)` projection set; and
3. the archive encoding/compression profile.

Remote destination is a fourth, downstream transport parameter. This keeps a
future Parquet mapping, OCSF revision, deterministic compressor, or storage
adapter from changing canonical evidence identity or reopening the run.
Registrations are code-owned and non-executable; this is not a third-party
plugin loader.

## Whole-Repository Scope

The implementation will cross these repository and runtime surfaces:

- experiment admission and persisted source identity under
  `src/aptl/core/experiment/`;
- final run/apparatus/seal production from the dependency work;
- evidence, provenance, correlation, run-store, redaction, path-safety, and
  exporter boundaries under `src/aptl/core/` and `src/aptl/utils/`;
- deterministic archive precedents under `src/aptl/appliance/`;
- `src/aptl/cli/runs.py` and `aptl.cli._common` for the local operator surface;
- `src/aptl/api/**` only if a later authenticated download surface is added;
- `mcp/mcp-red`, `mcp/aptl-mcp-common`, and their tests only if the OCSF
  taxonomy/mapping or shared redaction contract changes;
- RAES corpus/schema/conformance resources from the pinned distribution;
- `pyproject.toml`, `uv.lock`, and hashed requirements if Parquet support adds
  an optional dependency;
- `.ground-control.yaml`, `.gc/plan-rules.md`, pytest/fuzz/security tests,
  pre-commit, and docs; and
- host filesystem/archive APIs and, only after local completion, the existing
  SDK-based remote-export boundary.

No Docker/Compose/container/config change is inherent to EXP-008. If the
implementation introduces one, it has crossed the intended boundary and must
justify that expansion plus the clean-lab validation gate.

## Gotchas And Anti-Patterns

- Wrapping `export_local()` and treating its tarball as deterministic or sealed.
- Writing checksums, projections, or inventory back into the source run.
- Scanning the run directory and calling every file “evidence.”
- Re-reading mutable project task/spec/scenario files at export time.
- Treating `ready-to-seal`, `sealed-ready`, or a run-status string as a
  verified seal.
- Sealing canonical sources while leaving bundle-time projections outside the
  signed/rooted closure.
- Creating `Aces*`, `ExperimentBundleTask`, or local Pydantic mirrors of RAES
  task/run/apparatus/capture/evidence contracts.
- Reintroducing removed `aces_*` imports or emitting new legacy `aces` record
  sections.
- Dumping validated models and claiming the reserialized bytes are the original
  canonical artifact.
- Copying all RAES schemas/fixtures instead of the exact published schemas
  needed by the bundle.
- Treating an APTL run record, range snapshot, provenance section, or
  correlation graph as the RAES run/apparatus/evidence contract.
- Flattening null, missing, unavailable, withheld, and redacted into one empty
  value.
- Letting Parquet coerce identifiers/large integers to floats or timestamps to
  local time.
- Generating OCSF classifications independently from the existing TypeScript
  taxonomy, or calling an aligned projection officially conformant without a
  pinned schema and validator.
- Exporting detection scores, coverage, charts, significance, benchmark
  rankings, claims, or publication recommendations.
- Using raw filenames, URIs, media types, archive headers, or CSV cells as
  trusted control data.
- Using `tar.add(run_path)`, `extractall()`, symlink-following reads, path
  prefix checks followed by reopen, or unbounded decompression/parsing.
- Adding another checksum helper, path validator, redactor, persistence
  repository, exception hierarchy, or workflow state machine.
- Passing signing keys, SDK credentials, tokens, source values, or paths in
  argv, URLs, logs, diagnostics, tags, or bundle metadata.
- Uploading a mutable side manifest separately from the verified bundle.

## Non-Goals And Boundaries

- No statistical analysis, hypothesis testing, effect sizes, benchmark
  scoring, charts, significance markers, interpretation, or claim selection.
- No certification that a bundle or dataset is publishable, representative,
  scientifically adequate, anonymous, or fit for a particular study.
- No first redaction boundary and no weakening of ADR-029 or participant
  visibility.
- No new experiment, task, run, apparatus, capture, evidence, correlation,
  provenance, OCSF, or seal schema where an incumbent owns the concept.
- No recovery of absent evidence, fabrication of checksums, or substitution of
  current files for historical sealed bytes.
- No remote collection, network resolution, automatic upload, data lake,
  query engine, notebook, analytics pipeline, or database repository.
- No CSV projection in the initial contract.
- No redesign of deployment backends, lab lifecycle, collectors, web auth,
  MCP authority, OTel, or the participant runtime.
