---
id: REP-006
title: "Comparable Precondition Inspection Between Runs"
status: DRAFT
type: FUNCTIONAL
priority: WONT
wave: 3
created_at: 2026-03-21T07:53:08.566586Z
updated_at: 2026-10-05T07:51:12.874346Z
---

# REP-006: Comparable Precondition Inspection Between Runs

## Statement

APTL shall produce a machine-readable inspection of explicitly comparability-relevant preconditions for two sealed ACES runs: task and scenario identities, condition assignment, non-secret parameters, stochastic controls, apparatus and participant manifests, configuration and content digests, capture plan, clock context, limitations, and missing evidence. The report shall distinguish equal, changed, unavailable, and not-comparable fields and shall consume ACES cross-run comparability semantics when published. It shall not infer root cause, statistical significance, regression, or performance conclusions.

## Rationale

WITHDRAWN 2026-10-05: RAES owns cross-run comparison (rae#269, rae#270). See GitHub issue #496. --- Original rationale: Researchers need to know what changed before interpreting differing results. A factual precondition inspection belongs at the instrument boundary; comparison semantics are owned by ACES and analytical conclusions are downstream.

## Traceability

- DOCUMENTS → GITHUB_ISSUE `#496` (REP-006: Comparable precondition inspection between runs)
