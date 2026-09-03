# ADR-050: Terminal Attempt Archival And Atomic Seal Boundary

## Status

accepted

## Date

2026-07-28

## Context

EXP-009 requires one conformant `experiment-run-v1` record for every terminal
execution attempt, including retries, cancellations, interruptions, failures,
and invalidations. It also requires raw evidence records, immutable sealing,
crash recovery, and local discovery without creating a second portable run
schema.

APTL already has the contract and collection pieces:

- public RAES `ExperimentRunModel`, `ExperimentEvidenceRecordModel`, apparatus,
  participant, stochastic, clock, artifact, result-summary, and traceability
  models and their cross-artifact validators;
- immutable admitted trial plans and planned-trial identities from ADR-047;
- the EXP-010 evidence coordinator, content-addressed blobs, and evidence
  records;
- REP-003 ready-to-seal provenance and OBS-002 correlation/clock projections;
  and
- `RunStorageBackend`, `LocalRunStore`, shared redaction, and descriptor-relative
  no-follow containment.

Two incumbent choices cannot be carried into EXP-009 unchanged:

- ADR-047 says a planned-trial ID becomes the execution `run_id`. A retry is a
  new execution attempt of the same planned trial, so reusing that ID would
  either overwrite the first attempt or make the second finalization conflict
  with it.
- Lab startup currently writes an overwrite-capable APTL
  `aptl.run-record/v2` payload to `manifest.json`, labels it successful, and
  treats archival failure as non-fatal. Startup does not own a terminal
  attempt's outcome, evaluator results, evidence completeness, or final seal.

The current persistence helpers also do not by themselves implement an archive
transaction. `write_json`/`append_jsonl` are mutable, while the create-once
path publishes its final filename before all bytes and parent-directory
durability are guaranteed. `export_local()` currently adds
`checksums.sha256` to the run directory during export, which would mutate an
already sealed archive.

## Decision

### Planned-trial identity and attempt identity are distinct

The admitted `planned_trial_id` remains the stable identity of planned work.
Every actual execution attempt receives a distinct, filesystem-safe
`attempt_id`, and that attempt identity is the portable
`ExperimentRunModel.run_id` and the run archive directory identity.

A retry keeps the same plan and planned-trial reference but receives a new
attempt/run ID. Portable retry and repair lineage use RAES run references and
versions (`used_refs`, `derived_from_refs`, `generated_refs`, and, where
applicable, `invalidation.superseded_by`); APTL does not add a local
`retry_of`, `parent_run_id`, or attempt schema to the portable record.

This decision narrowly supersedes ADR-047's statement that the planned-trial ID
is reused as the execution `run_id`. It does not change ADR-047's deterministic
plan identity, admitted-plan digest, or no-replanning rule.

### The RAES run model is the only new portable run record

For EXP-009 attempts, `manifest.json` contains the canonical serialized public
RAES `ExperimentRunModel` (`schema_version="experiment-run/v1"`). The installed
RAES models, serializers, corpus fixtures, and task/run cross-artifact
validators remain authoritative. No APTL model mirrors their fields.

The existing `aptl.run-record/v2` shape becomes legacy read compatibility, not
a second final record. Startup-only observations move to explicitly
provisional artifacts and never occupy or overwrite the terminal manifest
path. Readers migrate to the RAES manifest and may retain a bounded,
read-only adapter for archives already written in the legacy shape. They do
not emit both permanent models for a new attempt.

### One terminal-attempt coordinator owns finalization

The execution lifecycle invokes one archival coordinator exactly once when an
attempt reaches any terminal cause. The coordinator receives the immutable
admitted plan/trial, the distinct attempt identity and retry predecessor, the
observed runtime/apparatus and participant state, evidence-acquisition result,
evaluator-supplied summaries, lifecycle terminal cause, clock provider, and
the injected run store. It does not rediscover any of those facts from current
configuration, active-session state, timestamps, or arbitrary archive paths.

The coordinator composes public RAES records from owner-native values. It does
not calculate metrics, infer result values from workflow state, reconstruct
missing captures, probe Docker, or introduce another execution state machine.
Terminal-cause-to-RAES status mapping is one code-owned policy used by every
caller:

- completed execution maps to `completed` with the evaluator's outcome;
- scenario/evaluator failure maps to `failed`;
- cancellation, policy stop, or infrastructure interruption maps to
  `aborted`;
- evidence loss or another validity failure maps to `invalidated` with
  `ExperimentInvalidationModel`; and
- a replaced record version maps to `superseded`.

The archive seal is separate from `ExperimentRunModel.run_status`; it must not
erase the execution outcome by forcing every portable record to
`run_status="sealed"`.

### A seal marker is the atomic commit point

Evidence blobs and evidence records, final provenance, correlation/clock
disclosures, and the canonical run manifest are immutable inputs to one seal.
A run is discoverable as sealed only after a store-owned commit marker has
been atomically published. The marker binds:

- the canonical run-record digest and version;
- every included artifact's relative path, media type, size, and checksum;
- evidence-record and provenance identities;
- the applicable seal/profile and contract versions; and
- an explicit completeness/limitation statement.

The store must write and verify complete bytes, `fsync` files and the containing
directory as required by the local durability contract, then publish the marker
with no-follow, no-replace semantics. A crash before the marker leaves an
unsealed recovery candidate, never a partially sealed run. Identical
finalization is idempotent; differing bytes for the same attempt/version are a
conflict. Once the marker exists, every structured, opaque, Python, MCP, and
export path treats the archive as immutable.

This is a narrow hardening of the existing `RunStorageBackend` /
`LocalRunStore` boundary, not a new archive repository. The final path must not
use overwrite-capable `write_json`, a single unchecked `os.write`, or a
post-write checksum pass as its commit primitive.

Sealed repair does not edit the archive. It produces a new run version or a
separate attestation with RAES lineage to the original bytes.

### The local index is a derived recovery journal

The local discovery index contains only bounded routing facts: attempt/run ID,
run version, manifest digest, seal state, terminal timestamp, and safe relative
record location. It is not portable and does not duplicate task, apparatus,
parameter, result, evidence, or provenance fields.

Index publication uses a prepared/committed append protocol under a store-owned
lock. A prepared entry names the exact expected manifest/seal identity before
the seal marker is committed; a committed entry follows it. After a crash, the
reader can reconcile a prepared entry by checking only its validated attempt
path, without scanning or trusting arbitrary filesystem paths. Readers validate
IDs, bounds, canonical line shape, duplicate/conflict rules, and referenced
seal bytes; they ignore or quarantine a partial trailing line.

The index is rebuildable from validated sealed archives by an explicit repair
operation. Its loss never changes the portable record or seal.

### Export and projections are read-only after sealing

Exporters package and verify already sealed bytes. They do not add checksum
files, redact, normalize, repair, or otherwise modify a run directory.
CLI/API/correlation compatibility projections read the canonical record and
seal inventory; they are never another normalization or persistence authority.

## Consequences

### Positive

- Retries are separate immutable scientific observations while retaining one
  planned-trial identity.
- A single portable RAES schema replaces the legacy APTL terminal manifest.
- The seal marker gives crash recovery an unambiguous commit point.
- The local index accelerates discovery without becoming a competing schema.
- Existing evidence, provenance, correlation, redaction, and containment
  boundaries remain the owners of their concerns.

### Negative And Risks

- Existing consumers of `aptl.run-record/v2` require a migration adapter.
- The run-store boundary needs stronger durable, no-replace publication and
  locked append semantics than its current helpers provide.
- MCP and other direct writers must be quiesced before sealing and must honor
  the same configured run root and sealed-state check.
- A crash can leave unsealed candidates or prepared index entries; recovery
  must reconcile them explicitly.

## Non-Goals

- Defining metrics, deriving statistics, comparing conditions, or replacing
  evaluator authority.
- Defining another experiment, run, evidence, apparatus, provenance, or retry
  schema.
- Adding a database, remote archive service, generic event bus, plugin loader,
  or new execution workflow engine.
- Treating checksums as a signature or third-party authenticity claim.
- Making raw evidence participant-visible merely because it is in the sealed
  archive.
- Repairing sealed bytes in place.

## References

- EXP-009 / GitHub issue #444.
- [ADR-029](adr-029-control-plane-secret-handling.md): shared secret boundary.
- [ADR-033](adr-033-agent-reasoning-trace-boundary.md): run-scoped capture and
  correlation identity.
- [ADR-044](adr-044-raes-aligned-run-reproducibility-record.md): RAES-aligned
  run composition.
- [ADR-047](adr-047-raes-experiment-admission-and-trial-plan-boundary.md):
  immutable admitted plans and the narrowly superseded run-ID clause.
- [EXP-010 preflight](../architecture/exp-010-capture-admission-evidence-preflight.md):
  evidence admission and acquisition.
- [REP-003 preflight](../architecture/rep-003-run-scoped-provenance-preflight.md):
  ready-to-seal provenance.
