# Issue #1201: transcript evidence redaction preflight

## Decision and boundaries

The TechVault adapter owns a new retained transcript payload version. Render a
structural collection such as `transcript_entries`, with a non-replayable,
domain-separated `terminal_ref` instead of each raw `session_id`. Retain ordered
frames, timestamps, direction, close reason, and the broker-validated custody
digest under the explicit name `source_chain_digest`. Choose every retained key
against `aptl.utils.redaction.is_sensitive_key`; the shared recursive redactor
must still inspect frame `data` and redact secret-shaped values. Neither
`sessions`, `session_id`, nor `session_count` is safe as a retained key. Keep
trusted counts outside the redacted payload or choose safe structural names.
Do not allowlist `sessions` globally or weaken the Python/TypeScript redaction
parity contract.

`source_chain_digest` records the *unredacted source frame chain* that
the broker and `RedteamSessionTranscriptSource` validate. It cannot be
recomputed from redacted frame data and must not be described as a checksum of
the retained payload. `raw_content.content_checksum`, the blob URI digest,
and the bundle inventory digest identify the *retained redacted bytes*.
Domain-separate the `terminal_ref` derivation and bind it to session plus
custody identity; do not publish a raw or replayable session ID. Keep the
derivation deterministic for the same source and independent of secrets that
would need to be stored or passed in an environment/argv. An unkeyed digest of
a predictable ID does not promise anonymity, and a source digest is an
equality fingerprint, not proof that redacted text is original. `terminal_ref`
is an evidence label only; no session/auth lookup may accept it as authority.

The raw broker export's `sessions`, `session_id`, `final_chain_digest`, and
`expected_session_ids` remain input/custody concepts. Do not rename the broker
protocol, MCP census, `APTL_SESSION_ID`, or the existing capture registration
and RAES artifact role to match the retained payload. The adapter's retained
payload is a versioned projection, not a second source of custody truth.

## Required incumbent gates

| Layer | Incumbent and required behavior |
| --- | --- |
| Authority and input | `raes_evidence_acquisition.py` quiesces the broker, reads the independent MCP census through no-follow paths, reconciles the broker authority/run/plan/binding, and resolves the exact installed `ScenarioCaptureContribution`. `_compose_capture_apparatus.py` reconciles accepted IDs. `transcript_parsing.py` enforces binding pin, export shape and limits; `techvault_transcript.py` enforces census, order, time, UTF-8, loss, and chain. Preserve these checks before projection. |
| Secret handling | `_persist.py` applies the binding's trusted `redact_secrets` handler to complete bounded JSON before storage. `redaction.py` and MCP common `redaction.ts` own the fail-closed taxonomy. Test actual retained frame values; structural keys must survive recursion without suppressing value redaction. Preserve depth and byte-limit failures as failures. |
| Persistence and identity | `acquire_evidence`, `content_store.create_content_addressed`, `LocalRunStore` and `records.build_evidence_record` own quotas, contained create-once writes, run locking, retained checksums, record IDs, and RAES DTOs. Read the actual `EvidenceRef.content_uri` through the existing no-follow run-store/pathsafe reader for semantic qualification. Do not add an evidence store, checksum field to the RAES record, or a parallel record schema. |
| Terminal outcome | A known nonempty expected census cannot yield `EMPTY_OK`, `SEALED_READY`, or a finalized marker if the retained collection is absent, collapsed, empty, or has mismatched transcript/frame counts. Feed a semantic failure through existing `CollectorStatus`/`AcquisitionDisposition` and fixed, redacted RAES diagnostics; do not expose source bytes or raw exception text. Preserve legitimate zero-session `EMPTY_OK` only when the admitted census is genuinely empty. |
| Bundle qualification | `_collect.py` and `_io.py` verify referenced records and blob checksums with bounded no-follow reads; `build.py` carries `ClosureLimitation` and validation disclosures; `verify.py` is a standalone byte/inventory verifier. The TechVault-aware qualification path must reject or name a malformed retained transcript specifically. Reuse one adapter-owned retained-payload semantic contract at finalization and at any TechVault-aware bundle qualification seam; keep the portable verifier generic and make its semantic limit explicit. Do not silently let a generic checksum success stand in for transcript qualification. |
| Host and observability | Existing fixed broker `container_exec` argv, sidecar volume/PID separation, `AptlConfig`/capture-binding validation, and private runtime environment remain unchanged. No transcript bytes, raw IDs, commands, or credentials in argv, env additions, logs, OTel, CLI output, `LabResult.error`, or diagnostic messages. `lab.py` must continue teardown after a required transcript finalization failure. |

The semantic validator belongs with the TechVault retained payload contract.
Parameterize it by payload version and optional trusted expected transcript
and frame counts: finalization has the source census/counters, while portable
bundle qualification may have only the retained payload and its bound record.
In the latter case, validate the self-contained schema and noncollapsed
structure, and disclose that independent census agreement was not checked.
That seam lets a later payload version or another adapter use the same generic
coordinator and bundle mechanisms without adding TechVault rules to them.
Validate after the shared redactor and readback, not only the collector's
pre-persistence document. Match an evidence record to its pinned registration
and run before applying the adapter contract; do not infer TechVault from an
arbitrary blob's filename or a self-declared JSON field.

## Verification and non-goals

The regression must run acquisition through persistence, read the stored
content URI, compare expected transcript and frame counts, prove raw IDs absent
and secret-shaped frame values redacted while benign content remains, and show
different source transcripts produce different retained digests. Exercise a
collapsed/empty retained collection against a nonempty census and a
malformed transcript in bundle qualification. Assert that the source-chain
digest matches the validated raw frames while the record checksum matches
only the retained blob. Use targeted pytest paths and staged `pre-commit run`
per `.gc/plan-rules.md`.

This issue does not change broker custody, MCP authorization, session ID
validation, Compose mounts, capture admission policy, generic redaction rules,
RAES evidence schemas, or the bundle's byte-level verification claim. Do not
introduce a new controller, exception hierarchy, logging channel, config flag,
or workflow to make the transcript appear complete.
