# Portable Evidence Bundle Export

The evidence bundle exporter packages a run's research evidence into a portable,
self-describing archive that a third party can validate without importing APTL
internals. It is the EXP-008 counterpart to the legacy `aptl runs export`
convenience tarball: instead of scanning the run directory, it packages a
verified artifact closure with a machine-readable inventory, the exact published
RAES schemas, and optional loss-accounted projections.

Export is packaging and projection only. It performs no statistical analysis, no
claim selection, and no publishability certification, and it is never the first
redaction boundary. Redaction happens upstream at the persistence boundary
(ADR-029).

## Build a bundle

```bash
# Local, offline bundle with the JSONL and Parquet projections.
aptl runs export-bundle <run_id> -o ./exports -p jsonl -p parquet

# Canonical artifacts only (no projections).
aptl runs export-bundle <run_id> -o ./exports
```

Options:

- `--projection / -p` selects a derived projection: `jsonl`, `parquet`, or
  `ocsf`. Repeat the flag for more than one. Parquet requires the optional
  `pyarrow` dependency (`pip install aptl[parquet]`); without it, the bundle
  records a `projection-unavailable` limitation instead of failing.
- `--output-dir / -o` is the destination directory. It must be outside the run
  tree, and the exporter never overwrites an existing bundle.
- `--verify / --no-verify` controls the local self-verification pass that runs
  after the archive is written (on by default).

The command reports the bundle path, the reproducible root identity, the member
count, the seal state, and any disclosed limitations.

## Verify a bundle

```bash
aptl runs verify-bundle ./exports/<run_id>.evidence-bundle.tar
```

Verification streams the archive, enforces its own resource bounds, recomputes
every member digest and size against the inventory, recomputes the reproducible
root identity, and, when a seal claims to be verified, checks that the seal
binds that root. The verifier depends only on the standard library and the JSON
canonicalization library, so a third party can lift it out of the tree and run
it anywhere.

## Bundle layout

```
<run_id>.evidence-bundle.tar
  bundle.json                              # aptl-evidence-bundle/v1 envelope
  backend/run-manifest.json                # APTL/backend-owned evidence
  backend/run-provenance.json
  backend/correlation.json
  evidence/records/<record_id>.json        # canonical RAES evidence records
  evidence/blobs/<sha256>                   # referenced raw observation bytes
  schemas/experiment-core/...-v1.json       # exact published RAES JSON Schemas
  projections/jsonl/evidence-records.jsonl  # optional, loss-accounted
  projections/parquet/evidence-records.parquet
  projections/ocsf/mcp-side-ocsf.jsonl
```

Every regular file except the envelope has one inventory row that references it
by bundle path, logical role, canonical-versus-derived classification, source
reference, contract or mapping version, SHA-256 digest, byte size, media type,
and, where applicable, sensitivity, redaction, and loss disclosures. The
envelope never lists itself: a checksum surface does not include or rewrite
itself.

## The `aptl-evidence-bundle/v1` envelope

The envelope is the one APTL packaging schema the bundle adds. It never restates
a field a RAES artifact already owns; an inventory row references the canonical
artifact rather than copying its fields. The envelope carries the bundle
profile, the resource-limit profile, the seal state, the inventory, the data
dictionary, the projection descriptors, the validation disclosures, and the
limitations.

The data dictionary references the included RAES JSON Schema for each canonical
artifact. For a projection it additionally records the source contract and
field, the target field and physical type, the null and missing treatment, the
timestamp and integer encoding, the nested-reference handling, the mapping
identifier and version, and every known loss.

## Determinism

Two exports of the same run produce identical archives, aside from explicitly
excluded creation metadata. Inventory and packaging metadata use RFC 8785
canonical JSON with normalized `sha256:<hex>` identities and deterministic
ordering. The archive is an uncompressed USTAR with normalized member metadata
(owner, mode, and modification time) and members sorted by bundle path. The
reproducible root identity excludes wall-clock creation time; the default build
records no creation metadata at all, so its bytes are fully reproducible.

## Projections

Canonical source records and their references are always retained. Projections
are optional, derived, and admitted only through a closed, versioned mapping:

- **JSONL** emits one RFC 8785 canonical JSON object per row, so missing, null,
  unavailable, withheld, and redacted values, string identifiers, exact
  timestamps, and nested references are all preserved.
- **Parquet** keeps identifiers as strings even when digit-shaped, keeps
  timestamps as their exact source instant, encodes nested references as
  canonical JSON, and uses exact `int64`. Any integer outside `int64` becomes
  an exact decimal string with a declared loss disclosure rather than a
  floating-point value.
- **OCSF-aligned** includes the run's existing `mcp-side/ocsf.jsonl` derivative
  verbatim with an explicit APTL mapping and taxonomy version and its source
  tool-call references. It is aligned through the mcp-red taxonomy, not
  certified OCSF-conformant.

An unknown projection format fails closed.

## Security posture

Every source file is read through descriptor-relative, no-follow, one-open
containment, so a symlinked or traversing component is rejected rather than
followed. Bundle paths are code-owned and derived from validated identifiers and
content digests; a raw filename, URI, media type, or Unicode spelling never
becomes an archive path. Archive entry count, member size, total size, path
length and depth, and decompression ratio are bounded before allocation, and the
verifier never extracts to disk. Secret-shaped values in generated bundle
metadata are redacted with the shared ADR-029 redactor; canonical bytes are
never rewritten.

## Seal state and partial runs

The bundle consumes a verified seal produced by the run-finalization boundary
(issue #444). Until that boundary lands, the exporter reports the bundle as
`UNSEALED` with an explicit `seal-absent` limitation. A `ready-to-seal`
provenance state, a `SEALED_READY` disposition, a run manifest, or a
`checksums.sha256` file is never treated as a verified seal.

Partial, failed, invalid, and inconclusive runs remain exportable. Their
capture outcomes, provenance limitations, missing references, and redaction and
loss disclosures stay intact, and the exporter never upgrades such a run to
complete, successful, or publishable. A missing referenced source becomes a
stable `missing-source` limitation rather than a substituted or fabricated
artifact.
