---
id: EXP-009
title: "ACES Archival Run and Evidence Record Production"
status: ACTIVE
type: FUNCTIONAL
priority: MUST
wave: 2
created_at: 2026-03-24T03:20:03.458480Z
updated_at: 2026-07-29T00:16:58.337413Z
---

# EXP-009 — ACES Archival Run and Evidence Record Production

## Statement

For every terminal execution attempt, APTL shall atomically produce and seal a conformant ACES experiment-run-v1 record with task and scenario references, observed apparatus context, participant provenance, bound parameters, stochastic controls, clock context, status/outcome, deviations or invalidation, evidence artifacts, evaluator-supplied result summaries, traceability, and retry lineage. Raw captures shall be represented by experiment-evidence-record-v1 artifacts and content-addressed references. A local append-safe index may support discovery, but shall not become a competing portable run schema. Structured writes shall use the existing redaction and path-containment boundaries.

## Rationale

The principal output of a scientific instrument is trustworthy evidence with durable provenance. Emitting canonical ACES records makes APTL runs portable while atomic sealing, checksums, and redaction make interrupted or maliciously influenced runs auditable.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#444` (EXP-009 — ACES archival run and evidence record production)
- IMPLEMENTS → CODE_FILE `src/aptl/core/archival/coordinator.py` (Terminal-attempt archive coordinator (compose + validate + atomic seal, exactly once))
- IMPLEMENTS → CODE_FILE `src/aptl/core/archival/run_record.py` (Public RAES experiment-run/v1 composition + cross-artifact validation (the seal gate))
- IMPLEMENTS → CODE_FILE `src/aptl/core/archival/seal.py` (Atomic seal marker + closed inventory + byte/RAES-artifact identity join)
- IMPLEMENTS → CODE_FILE `src/aptl/core/archival/verify.py` (Canonical sealed-archive verifier (marker shape/identity + every inventory checksum))
- IMPLEMENTS → CODE_FILE `src/aptl/core/runstore.py` (Durable atomic create-once seal-marker commit + per-run write/seal exclusion + immutability)
- IMPLEMENTS → ADR `docs/adrs/adr-050-terminal-attempt-archival-and-atomic-seal.md` (ADR-050: Terminal Attempt Archival and Atomic Seal Boundary)
- TESTS → TEST `tests/test_archival_discovery_index.py` (Discovery index prepared/committed recovery + corruption/tamper surfacing)
- IMPLEMENTS → CODE_FILE `src/aptl/core/archival/discovery_index.py` (Append-safe prepared/committed discovery index with crash recovery)
- IMPLEMENTS → CODE_FILE `src/aptl/core/execution/executor.py` (Execution controller: drive admitted trials to finalize_terminal_attempt exactly once)
- TESTS → TEST `tests/test_archival_terminal_states.py` (Terminal-state fixture coverage: every terminal cause seals a conformant record)
- TESTS → TEST `tests/test_archival_seal.py` (Atomic seal commit, immutability, idempotency/conflict, inventory tamper detection)
- TESTS → TEST `tests/test_execution_executor.py` (Production-path integration: executor reaches sealing across every terminal cause + recovery)
